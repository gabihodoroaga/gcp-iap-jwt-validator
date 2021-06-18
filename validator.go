package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"k8s.io/klog/v2"

	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
)

const (
	serviceNameKey = "kubernetes.io/service-name"
	servicePortKey = "kubernetes.io/service-port"
	retryInterval  = 60 * time.Second
)

var (
	searchOpt    *searchOptions
	audience     string
	issuer       string         = "https://cloud.google.com/iap"
	httpPort     int            = 8081
	jwtValidator tokenValidator = gcpTokenValidator{}
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	klog.Info("starting GKE IAP Token validator")

	// read the httpPort
	port := os.Getenv("HTTP_PORT")
	if port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil {
			klog.Errorf("invalid configuration, HTTP_PORT must a number, found %q", port)
			os.Exit(1)
		}
		httpPort = portNumber
	}

	// search for issuer
	iss := os.Getenv("OAUTH_ISSUER")
	if iss != "" {
		issuer = iss
	}

	// read backend search options
	opt, err := parseSearchOptions()
	if err != nil {
		klog.Errorf("failed to configure search options: %v", err)
		os.Exit(1)
	}
	searchOpt = opt

	aud := os.Getenv("OAUTH_AUDIENCE")
	if aud != "" {
		audience = aud
	} else {
		// search for audience
		go getRequiredClaims()
	}

	// setup the http handler
	http.HandleFunc("/", validateJWT)
	klog.V(1).Infof("Running http server on :%v", httpPort)
	http.ListenAndServe(fmt.Sprintf(":%v", httpPort), nil)
}

// validateJWT validates a JWT found in the "x-goog-iap-jwt-assertion" header
// and return 200 if valid, 401 if the header is not present, and 403 if the validation fails
func validateJWT(w http.ResponseWriter, req *http.Request) {
	if klog.V(3).Enabled() {
		klog.Infof("request received from: %v, headers: %v", req.RemoteAddr, req.Header)
	}
	iapJWT := req.Header.Get("X-Goog-IAP-JWT-Assertion")
	if iapJWT == "" {
		klog.V(1).Infof("X-Goog-IAP-JWT-Assertion header not found")
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	if audience == "" {
		klog.V(1).ErrorS(fmt.Errorf("token cannot be validated, empty audience, check for previous errors"), "")
		http.Error(w, "", http.StatusForbidden)
		return
	}

	if issuer == "" {
		klog.V(1).ErrorS(fmt.Errorf("token cannot be validated, empty issuer, check for previous errors"), "")
		http.Error(w, "", http.StatusForbidden)
		return
	}

	ctx := context.Background()
	// we pass empty as audience here because we will validate it later
	payload, err := jwtValidator.Validate(ctx, iapJWT, "")
	klog.V(3).Infof("payload received: %+v", payload)
	if err != nil {
		klog.V(1).ErrorS(err, "error validating jwt token")
		http.Error(w, "", http.StatusForbidden)
		return
	}
	// empty payload should not be possible
	if payload == nil {
		klog.V(1).ErrorS(nil, "null payload received")
		http.Error(w, "", http.StatusForbidden)
		return
	}
	// validate the audience
	if audience != payload.Audience {
		klog.V(1).ErrorS(nil, "error validating jwt token, invalid audience, expected %s, got %s", audience, payload.Audience)
		http.Error(w, "", http.StatusForbidden)
		return
	}
	// validate the issuer
	if issuer != payload.Issuer {
		klog.V(1).ErrorS(nil, "error validating jwt token, invalid issuer, expected %s, got %s", issuer, payload.Issuer)
		http.Error(w, "", http.StatusForbidden)
		return
	}
	// validate expired - this may be redundant - but we check it anyway
	if payload.Expires == 0 || payload.Expires+30 < time.Now().Unix() {
		klog.V(1).ErrorS(nil, "error validating jwt token, expired")
		http.Error(w, "", http.StatusForbidden)
		return
	}

	// validate IssuedAt - should not be in the future
	if payload.IssuedAt == 0 || payload.IssuedAt-30 > time.Now().Unix() {
		klog.V(1).ErrorS(nil, "error validating jwt token, emitted in the future")
		http.Error(w, "", http.StatusForbidden)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// getRequiredClaims finds the audience require for token validation by querying
// the google apis
func getRequiredClaims() {

	resourceService, err := cloudresourcemanager.NewService(context.Background())
	if err != nil {
		klog.Fatalf("cannot create cloudresourcemanager api service")
	}

	projectsService := gcpProjectsAPIService{projectsService: resourceService.Projects}

	computeService, err := compute.NewService(context.Background())
	if err != nil {
		klog.Fatalf("cannot create compute api service")
	}

	backendsService := gcpBackendsAPIService{backendServicesService: computeService.BackendServices}

	// TODO: use a backoff strategy
	tick := time.NewTicker(retryInterval)
	defer tick.Stop()

	for {
		klog.V(3).Info("begin call to get the project number")
		projectNumber, err := getProjectNumber(projectsService)
		if err != nil {
			klog.Errorf("error retrieving project number: %v", err)
		}
		klog.V(3).Info("begin call to get the backend service id")
		backendServiceID, err := getBackendServiceID(backendsService)
		if err != nil {
			klog.Errorf("error retrieving backend service id: %v", err)
		}
		if err == nil {
			audience = fmt.Sprintf("/projects/%s/global/backendServices/%s", projectNumber, backendServiceID)
			klog.V(1).Infof("audience value found: %s, ready to validate requests", audience)
			return
		}
		klog.V(1).Infof("unable to retrieve the audience value, retring in %v seconds", retryInterval.Seconds())
		select {
		case <-tick.C:
		}
	}
}

func getProjectNumber(projectsService projectsAPIService) (string, error) {
	klog.V(3).Infof("begin call to projects api")
	project, err := projectsService.Get(searchOpt.projectID)
	if err != nil {
		return "", err
	}
	if klog.V(3).Enabled() {
		klog.Infof("project: %+v", project)
	}
	return strconv.FormatInt(project.ProjectNumber, 10), nil
}

func getBackendServiceID(backendServices backendsAPIService) (string, error) {

	// Get only the backends where IAP is enabled
	backends, err := backendServices.List("iap.enabled=true")
	if err != nil {
		return "", err
	}

	var foundBackend *compute.BackendService
	for _, backend := range backends {
		klog.V(1).Infof("checking backend %s", backend.Name)
		klog.V(3).Infof("backend %+v", backend)
		// try to match by oauth client id first
		if searchOpt.oauthClientID != "" && backend.Iap.Oauth2ClientId != searchOpt.oauthClientID {
			continue
		}
		// search for service name
		if searchOpt.serviceName != "" && !strings.Contains(backend.Name, searchOpt.serviceName) {
			continue
		}

		if searchOpt.serviceGkeName != "" || searchOpt.serviceGkePortName != "" || searchOpt.serviceGkePortNumber > 0 {
			// we need to parse the backend description now
			svcDesc, err := parseBackendDescription(backend.Description)
			if err != nil {
				klog.V(3).Infof("parse description error: %w", err)
				continue
			}
			// search by service name
			if searchOpt.serviceGkeName != "" && svcDesc.ServiceName != searchOpt.serviceGkeNamespace+"/"+searchOpt.serviceGkeName {
				continue
			}
			// search by port name
			if searchOpt.serviceGkePortName != "" &&
				(svcDesc.ServicePort.Name != searchOpt.serviceGkePortName ||
					searchOpt.serviceGkeName == "") {
				continue
			}
			// search by port number
			if searchOpt.serviceGkePortNumber != 0 &&
				(svcDesc.ServicePort.Number != searchOpt.serviceGkePortNumber ||
					searchOpt.serviceGkeName == "") {
				continue
			}
		}
		// if we got here we found our backend
		if foundBackend == nil {
			foundBackend = backend
			// do not break here as we will search for duplicates
		} else {
			klog.Warning("more than one backend service found with the provided search options")
		}
	}

	if foundBackend != nil {
		return strconv.FormatUint(foundBackend.Id, 10), nil
	}

	return "", fmt.Errorf("Backend service not found")
}

// parseSearchOptions returns the backend search options from environment
// variables
func parseSearchOptions() (*searchOptions, error) {
	options := &searchOptions{}
	options.projectID = os.Getenv("PROJECT_ID")
	if options.projectID == "" {
		return nil, fmt.Errorf("invalid configuration, PROJECT_ID variable not found")
	}
	options.oauthClientID = os.Getenv("OAUTH_CLIENT_ID")
	options.serviceName = os.Getenv("SERVICE_NAME")
	options.serviceGkeNamespace = os.Getenv("SERVICE_GKE_NAMESPACE")
	if options.serviceGkeNamespace == "" {
		options.serviceGkeNamespace = "default"
	}
	options.serviceGkeName = os.Getenv("SERVICE_GKE_NAME")
	options.serviceGkePortName = os.Getenv("SERVICE_GKE_PORT_NAME")
	portNumber := os.Getenv("SERVICE_GKE_PORT_NUMBER")
	if portNumber != "" {
		portNumberValue, err := strconv.Atoi(portNumber)
		if err != nil {
			return nil, fmt.Errorf("invalid configuration, SERVICE_GKE_PORT_NUMBER must a number, found %q", portNumber)
		}
		options.serviceGkePortNumber = portNumberValue
	}

	// vaidate search options - at least one search options
	if options.oauthClientID == "" &&
		options.serviceName == "" &&
		options.serviceGkeName == "" {
		return nil, fmt.Errorf("Invalid configuration, at least one search criteria must be specified. Set one of the variables:  OAUTH_CLIENT_ID, SERVICE_NAME, SERVICE_GKE_NAME")
	}

	// validate search options - service number with service name
	if options.serviceGkeName == "" && options.serviceGkePortName != "" {
		klog.Warning("[warning] SERVICE_GKE_PORT_NAME without SERVICE_GKE_NAME, value will be ignored")
	}
	if options.serviceGkeName == "" && options.serviceGkePortNumber != 0 {
		klog.Warning("[warning] SERVICE_GKE_PORT_NUMBER without SERVICE_GKE_NAME, value will be ignored")
	}

	klog.Infof("search options: %+v", options)
	return options, nil
}

func parseBackendDescription(description string) (*serviceDescription, error) {
	if description == "" {
		return nil, fmt.Errorf("empty description")
	}
	data := make(map[string]interface{})
	if err := json.Unmarshal([]byte(description), &data); err != nil {
		return nil, fmt.Errorf("decode error: description: %s, err: %w", description, err)
	}
	svcDesc := serviceDescription{}
	if nameValue, ok := data[serviceNameKey]; ok {
		svcDesc.ServiceName = nameValue.(string)
	} else {
		return nil, fmt.Errorf("name key not found, key:%s, description: %s", serviceNameKey, description)
	}
	if portValue, ok := data[servicePortKey]; ok {
		servicePort := serviceBackendPort{}
		pattern := `{Name:(.*),Number:(\d*),}`
		reg := regexp.MustCompile(pattern)
		match := reg.FindStringSubmatch(portValue.(string))
		if match == nil {
			return nil, fmt.Errorf("port decode error, description: %s, must match regexp %s", description, pattern)
		}
		servicePort.Name = match[1]
		if match[2] != "" {
			port, err := strconv.Atoi(match[2])
			if err != nil {
				return nil, fmt.Errorf("port number parse error, description: %v, err: %w", description, err)
			}
			servicePort.Number = port
		}
		svcDesc.ServicePort = servicePort
	} else {
		return nil, fmt.Errorf("port key not found, key:%s, description: %s", serviceNameKey, description)
	}
	return &svcDesc, nil
}
