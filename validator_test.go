package main

import (
	"context"
	"fmt"
	"net/http"
	"net/textproto"
	"os"
	"reflect"
	"testing"
	"time"

	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/idtoken"
)

func TestParseOptions(t *testing.T) {
	testCases := []struct {
		desc      string
		env       map[string]string
		expected  searchOptions
		wantError bool
	}{
		{
			desc:      "project id is required",
			wantError: true,
		},
		{
			desc: "at least one search option is required, negative",
			env: map[string]string{
				"PROJECT_ID": "project_id",
			},
			expected: searchOptions{
				projectID: "project_id",
			},
			wantError: true,
		},
		{
			desc: "at least one search option is required, oauth client",
			env: map[string]string{
				"PROJECT_ID":      "project_id",
				"OAUTH_CLIENT_ID": "oauth client",
			},
			expected: searchOptions{
				projectID:           "project_id",
				oauthClientID:       "oauth client",
				serviceGkeNamespace: "default",
			},
			wantError: false,
		},
		{
			desc: "at least one search option is required, service name",
			env: map[string]string{
				"PROJECT_ID":   "project_id",
				"SERVICE_NAME": "service name",
			},
			expected: searchOptions{
				projectID:           "project_id",
				serviceName:         "service name",
				serviceGkeNamespace: "default",
			},
			wantError: false,
		},
		{
			desc: "at least one search option is required, service gke name",
			env: map[string]string{
				"PROJECT_ID":       "project_id",
				"SERVICE_GKE_NAME": "service gke name",
			},
			expected: searchOptions{
				projectID:           "project_id",
				serviceGkeName:      "service gke name",
				serviceGkeNamespace: "default",
			},
			wantError: false,
		},
		{
			desc: "set all values, positive",
			env: map[string]string{
				"PROJECT_ID":              "project_id",
				"OAUTH_CLIENT_ID":         "oauth-client",
				"SERVICE_NAME":            "service-name",
				"SERVICE_GKE_NAME":        "service-gke-name",
				"SERVICE_GKE_NAMESPACE":   "gke-namespace",
				"SERVICE_GKE_PORT_NAME":   "gke-port-name",
				"SERVICE_GKE_PORT_NUMBER": "80",
			},
			expected: searchOptions{
				projectID:            "project_id",
				oauthClientID:        "oauth-client",
				serviceName:          "service-name",
				serviceGkeName:       "service-gke-name",
				serviceGkeNamespace:  "gke-namespace",
				serviceGkePortName:   "gke-port-name",
				serviceGkePortNumber: 80,
			},
			wantError: false,
		},
		{
			desc: "invalid port number, expect error",
			env: map[string]string{
				"PROJECT_ID":              "project_id",
				"SERVICE_GKE_NAME":        "service-gke-name",
				"SERVICE_GKE_PORT_NUMBER": "abc",
			},
			wantError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {

			orig := map[string]string{}
			for k, v := range tc.env {
				orig[k] = os.Getenv(k)
				os.Setenv(k, v)
			}

			t.Cleanup(func() {
				for k, v := range orig {
					os.Setenv(k, v)
				}
			})

			got, err := parseSearchOptions()
			if tc.wantError {
				if err == nil {
					t.Errorf("%v: expect error, got nil", tc.desc)
				}
				return
			}

			if err != nil {
				t.Errorf("%v: got error %v", tc.desc, err)
				return
			}

			if !reflect.DeepEqual(tc.expected, *got) {
				t.Errorf("%v: expected %#v, got %#v", tc.desc,
					tc.expected,
					got)
			}
		})
	}
}
func TestGetBackendServiceID(t *testing.T) {
	testCases := []struct {
		desc      string
		searchOpt *searchOptions
		backends  []*compute.BackendService
		err       error
		expected  string
		wantError bool
	}{
		{
			desc: "search for service name",
			searchOpt: &searchOptions{
				projectID:   "project_id",
				serviceName: "dummy-service-name",
			},
			backends: []*compute.BackendService{
				{
					Name: "k8s1-dummy-service-name-xxx",
					Iap: &compute.BackendServiceIAP{
						Enabled: true,
					},
					Id: 123456,
				},
			},
			expected:  "123456",
			wantError: false,
		},
		{
			desc: "search for service name, negative",
			searchOpt: &searchOptions{
				projectID:   "project_id",
				serviceName: "dummy-service-name",
			},
			backends: []*compute.BackendService{
				{
					Name: "k8s1-random-service-name-xxx",
					Iap: &compute.BackendServiceIAP{
						Enabled: true,
					},
				},
			},
			wantError: true,
		},
		{
			desc: "search only in iap activated backends",
			searchOpt: &searchOptions{
				projectID:   "project_id",
				serviceName: "dummy-service-name",
			},
			backends: []*compute.BackendService{
				{
					Name: "k8s1-dummy-service-name-xxx",
				},
			},
			wantError: true,
		},
		{
			desc: "search for oauth client id, positive",
			searchOpt: &searchOptions{
				projectID:     "project_id",
				oauthClientID: "oauth-client-id",
			},
			backends: []*compute.BackendService{
				{
					Name: "k8s1-dummy-service-name-xxx",
					Iap: &compute.BackendServiceIAP{
						Enabled:        true,
						Oauth2ClientId: "oauth-client-id",
					},
					Id: 123456,
				},
			},
			expected:  "123456",
			wantError: false,
		},
		{
			desc: "search for oauth client id, negative",
			searchOpt: &searchOptions{
				projectID:     "project_id",
				oauthClientID: "oauth-service-name",
				serviceName:   "dummy-service-name",
			},
			backends: []*compute.BackendService{
				{
					Name: "k8s1-dummy-service-name-xxx",
					Iap: &compute.BackendServiceIAP{
						Enabled: true,
					},
				},
			},
			wantError: true,
		},
		{
			desc: "search for service k8s service name, no description",
			searchOpt: &searchOptions{
				projectID:      "project_id",
				serviceGkeName: "dummy-gke-name",
			},
			backends: []*compute.BackendService{
				{
					Name:        "k8s1-dummy-service-name-xxx",
					Description: "",
					Iap: &compute.BackendServiceIAP{
						Enabled: true,
					},
				},
			},
			wantError: true,
		},
		{
			desc: "search for service k8s service name",
			searchOpt: &searchOptions{
				projectID:           "project_id",
				serviceGkeNamespace: "default",
				serviceGkeName:      "dummy-gke-name",
			},
			backends: []*compute.BackendService{
				{
					Name:        "k8s1-dummy-service-name-xxx",
					Description: `{"kubernetes.io/service-name":"default/dummy-gke-name","kubernetes.io/service-port":"\u0026ServiceBackendPort{Name:,Number:80,}","x-features":["NEG"]}`,
					Iap: &compute.BackendServiceIAP{
						Enabled: true,
					},
					Id: 123456,
				},
			},
			expected:  "123456",
			wantError: false,
		},
		{
			desc: "search for service k8s service name, negative",
			searchOpt: &searchOptions{
				projectID:           "project_id",
				serviceGkeNamespace: "default",
				serviceGkeName:      "dummy-gke-name",
			},
			backends: []*compute.BackendService{
				{
					Name:        "k8s1-dummy-service-name-xxx",
					Description: `{"kubernetes.io/service-name":"default/random-gke-name","kubernetes.io/service-port":"\u0026ServiceBackendPort{Name:,Number:80,}","x-features":["NEG"]}`,
					Iap: &compute.BackendServiceIAP{
						Enabled: true,
					},
				},
			},
			wantError: true,
		},
		{
			desc: "search for service k8s service port name",
			searchOpt: &searchOptions{
				projectID:           "project_id",
				serviceGkeNamespace: "default",
				serviceGkeName:      "dummy-gke-name",
				serviceGkePortName:  "dummy-gke-port-name",
			},
			backends: []*compute.BackendService{
				{
					Name:        "k8s1-dummy-service-name-xxx",
					Description: `{"kubernetes.io/service-name":"default/dummy-gke-name","kubernetes.io/service-port":"\u0026ServiceBackendPort{Name:dummy-gke-port-name,Number:80,}","x-features":["NEG"]}`,
					Iap: &compute.BackendServiceIAP{
						Enabled: true,
					},
					Id: 123456,
				},
			},
			expected:  "123456",
			wantError: false,
		},
		{
			desc: "search for service k8s service port name,negative",
			searchOpt: &searchOptions{
				projectID:           "project_id",
				serviceGkeNamespace: "default",
				serviceGkePortName:  "dummy-gke-port-name",
			},
			backends: []*compute.BackendService{
				{
					Name:        "k8s1-dummy-service-name-xxx",
					Description: `{"kubernetes.io/service-name":"default/random-gke-name","kubernetes.io/service-port":"\u0026ServiceBackendPort{Name:dummy-gke-port-name,Number:80,}","x-features":["NEG"]}`,
					Iap: &compute.BackendServiceIAP{
						Enabled: true,
					},
				},
			},
			wantError: true,
		},
		{
			desc: "search for service k8s service port number",
			searchOpt: &searchOptions{
				projectID:            "project_id",
				serviceGkeNamespace:  "default",
				serviceGkeName:       "dummy-gke-name",
				serviceGkePortNumber: 80,
			},
			backends: []*compute.BackendService{
				{
					Name:        "k8s1-dummy-service-name-xxx",
					Description: `{"kubernetes.io/service-name":"default/dummy-gke-name","kubernetes.io/service-port":"\u0026ServiceBackendPort{Name:,Number:80,}","x-features":["NEG"]}`,
					Iap: &compute.BackendServiceIAP{
						Enabled: true,
					},
					Id: 123456,
				},
			},
			expected:  "123456",
			wantError: false,
		},
		{
			desc: "search for service k8s service port number,negative",
			searchOpt: &searchOptions{
				projectID:            "project_id",
				serviceGkeNamespace:  "default",
				serviceGkePortNumber: 80,
			},
			backends: []*compute.BackendService{
				{
					Name:        "k8s1-dummy-service-name-xxx",
					Description: `{"kubernetes.io/service-name":"default/random-gke-name","kubernetes.io/service-port":"\u0026ServiceBackendPort{Name:,Number:80,}","x-features":["NEG"]}`,
					Iap: &compute.BackendServiceIAP{
						Enabled: true,
					},
				},
			},
			wantError: true,
		},
		{
			desc: "search for service k8s service name, port name and port number",
			searchOpt: &searchOptions{
				projectID:            "project_id",
				serviceGkeNamespace:  "default",
				serviceGkeName:       "gke-service-name",
				serviceGkePortName:   "gke-service-port-name",
				serviceGkePortNumber: 80,
			},
			backends: []*compute.BackendService{
				{
					Name:        "k8s1-dummy-service-name-xxx",
					Description: `{"kubernetes.io/service-name":"default/gke-service-name","kubernetes.io/service-port":"\u0026ServiceBackendPort{Name:gke-service-port-name,Number:80,}","x-features":["NEG"]}`,
					Iap: &compute.BackendServiceIAP{
						Enabled: true,
					},
					Id: 123456,
				},
			},
			expected:  "123456",
			wantError: false,
		},
		{
			desc: "search for service k8s service name, port name and port number,negative",
			searchOpt: &searchOptions{
				projectID:            "project_id",
				serviceGkeNamespace:  "default",
				serviceGkeName:       "gke-service-name",
				serviceGkePortName:   "gke-service-port-wrong-name",
				serviceGkePortNumber: 0,
			},
			backends: []*compute.BackendService{
				{
					Name:        "k8s1-dummy-service-name-xxx",
					Description: `{"kubernetes.io/service-name":"default/gke-service-name","kubernetes.io/service-port":"\u0026ServiceBackendPort{Name:gke-service-port-name,Number:80,}","x-features":["NEG"]}`,
					Iap: &compute.BackendServiceIAP{
						Enabled: true,
					},
				},
			},
			wantError: true,
		},
		{
			desc: "search for service k8s service name,malformed description",
			searchOpt: &searchOptions{
				projectID:           "project_id",
				serviceGkeNamespace: "default",
				serviceGkeName:      "dummy-gke-name",
			},
			backends: []*compute.BackendService{
				{
					Name:        "k8s1-dummy-service-name-xxx",
					Description: `{"kubernetes.io/service-name":"default/dummy-gke-name","kubernetes.io/service-port":"\u0026ServiceBackendPort{Name:,Number:80,}","x-features":["NEG"]`,
					Iap: &compute.BackendServiceIAP{
						Enabled: true,
					},
				},
			},
			wantError: true,
		},
		{
			desc: "search for service k8s service name,wrong keys",
			searchOpt: &searchOptions{
				projectID:           "project_id",
				serviceGkeNamespace: "default",
				serviceGkeName:      "dummy-gke-name",
			},
			backends: []*compute.BackendService{
				{
					Name:        "k8s1-dummy-service-name-xxx",
					Description: `{"kubernetes.io/service-name-xxx":"default/dummy-gke-name","kubernetes.io/service-port":"\u0026ServiceBackendPort{Name:,Number:80,}","x-features":["NEG"]}`,
					Iap: &compute.BackendServiceIAP{
						Enabled: true,
					},
				},
			},
			wantError: true,
		},
		{
			desc: "google api returns error",
			searchOpt: &searchOptions{
				projectID:           "project_id",
				serviceGkeNamespace: "default",
				serviceGkeName:      "dummy-gke-name",
			},
			err:       fmt.Errorf("google api error"),
			wantError: true,
		},
		{
			desc: "multiple backends,return first with warning",
			searchOpt: &searchOptions{
				projectID:   "project_id",
				serviceName: "dummy-service-name",
			},
			backends: []*compute.BackendService{
				{
					Name: "k8s1-dummy-service-name-1-xxx",
					Iap: &compute.BackendServiceIAP{
						Enabled: true,
					},
					Id: 100,
				},
				{
					Name: "k8s1-dummy-service-name-2-xxx",
					Iap: &compute.BackendServiceIAP{
						Enabled: true,
					},
					Id: 200,
				},
			},
			expected:  "100",
			wantError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			searchOpt = tc.searchOpt
			fakeService := fakeBackendsAPIService{backends: tc.backends, err: tc.err}
			got, err := getBackendServiceID(fakeService)
			if tc.wantError {
				if err == nil {
					t.Errorf("%v: expect error, got nil", tc.desc)
				}
				return
			}

			if err != nil {
				t.Errorf("%v: got error %v", tc.desc, err)
				return
			}

			if tc.expected != got {
				t.Errorf("%v: expected %#v, got %#v", tc.desc,
					tc.expected,
					got)
			}
		})
	}

}

func TestGetProjectNumber(t *testing.T) {
	testCases := []struct {
		desc      string
		searchOpt *searchOptions
		project   *cloudresourcemanager.Project
		err       error
		expected  string
		wantError bool
	}{
		{
			desc: "get project number,valid",
			searchOpt: &searchOptions{
				projectID:           "project_id",
				serviceGkeNamespace: "default",
				serviceGkeName:      "dummy-gke-name",
			},
			project: &cloudresourcemanager.Project{
				ProjectNumber: 123456,
			},
			expected:  "123456",
			wantError: false,
		},
		{
			desc: "get project number,handle error",
			searchOpt: &searchOptions{
				projectID:           "project_id",
				serviceGkeNamespace: "default",
				serviceGkeName:      "dummy-gke-name",
			},
			project:   nil,
			err:       fmt.Errorf("from from api"),
			wantError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			searchOpt = tc.searchOpt
			fakeService := fakeProjectsAPIService{project: tc.project, err: tc.err}
			got, err := getProjectNumber(fakeService)
			if tc.wantError {
				if err == nil {
					t.Errorf("%v: expect error, got nil", tc.desc)
				}
				return
			}

			if err != nil {
				t.Errorf("%v: got error %v", tc.desc, err)
				return
			}

			if tc.expected != got {
				t.Errorf("%v: expected %#v, got %#v", tc.desc,
					tc.expected,
					got)
			}
		})
	}
}

func TestParseBackendDescription(t *testing.T) {
	testCases := []struct {
		desc               string
		backendDescription string
		expected           *serviceDescription
		wantError          bool
	}{
		{
			desc:               "no description",
			backendDescription: `{"kubernetes.io/service-name":"default/backend-service","kubernetes.io/service-port":"\u0026ServiceBackendPort{Name:port-name,Number:80,}","x-features":["NEG"]}`,
			expected: &serviceDescription{
				ServiceName: "default/backend-service",
				ServicePort: serviceBackendPort{
					Name:   "port-name",
					Number: 80,
				},
			},
			wantError: false,
		},
		{
			desc:      "no description",
			wantError: true,
		},
		{
			desc:               "malformed description",
			backendDescription: `{"kubernetes.io/service-name":`,
			wantError:          true,
		},
		{
			desc:               "wrong name key",
			backendDescription: `{"kubernetes.io/wrong-key-for-service":"default/backend-service","kubernetes.io/service-port":"\u0026ServiceBackendPort{Name:,Number:80,}","x-features":["NEG"]}`,
			wantError:          true,
		},
		{
			desc:               "wrong port key",
			backendDescription: `{"kubernetes.io/service-name":"default/backend-service","kubernetes.io/wrong-service-port":"\u0026ServiceBackendPort{Name:,Number:80,}","x-features":["NEG"]}`,
			wantError:          true,
		},
		{
			desc:               "wrong port value format",
			backendDescription: `{"kubernetes.io/service-name":"default/backend-service","kubernetes.io/service-port":"wrong port value format","x-features":["NEG"]}`,
			wantError:          true,
		},
		{
			desc:               "invalid number for port ",
			backendDescription: `{"kubernetes.io/service-name":"default/backend-service","kubernetes.io/service-port":"\u0026ServiceBackendPort{Name:,Number:12345678901234567890,}","x-features":["NEG"]}`,
			wantError:          true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := parseBackendDescription(tc.backendDescription)
			if tc.wantError {
				if err == nil {
					t.Errorf("%v: expect error, got nil", tc.desc)
				}
				return
			}

			if err != nil {
				t.Errorf("%v: got error %v", tc.desc, err)
				return
			}

			if !reflect.DeepEqual(tc.expected, got) {
				t.Errorf("%v: expected %#v, got %#v", tc.desc,
					tc.expected,
					got)
			}
		})
	}

}

func TestValidateJWT(t *testing.T) {

	testCases := []struct {
		desc       string
		issuer     string
		audience   string
		header     http.Header
		payload    *idtoken.Payload
		err        error
		statusCode int
	}{
		{
			desc:     "valid token",
			issuer:   "test-issuer",
			audience: "test/audience",
			header: http.Header{
				"X-Goog-IAP-JWT-Assertion": {"token"},
			},
			payload: &idtoken.Payload{
				Issuer:   "test-issuer",
				Audience: "test/audience",
				Expires:  time.Now().Unix() + 300, // after 5 min
				IssuedAt: time.Now().Unix() - 300, // 5 minutes ago
			},
			err:        nil,
			statusCode: 200,
		},
		{
			desc:     "invalid token",
			audience: "test audience",
			header: http.Header{
				"X-Goog-IAP-JWT-Assertion": {"token"},
			},
			payload:    nil,
			err:        fmt.Errorf("token validation error"),
			statusCode: 403,
		},
		{
			desc:       "no header",
			header:     http.Header{},
			statusCode: 401,
		},
		{
			desc: "empty header value",
			header: http.Header{
				"X-Goog-IAP-JWT-Assertion": {""},
			},
			statusCode: 401,
		},
		{
			desc: "empty audience",
			header: http.Header{
				"X-Goog-IAP-JWT-Assertion": {"token"},
			},
			statusCode: 403,
		},
		{
			desc:     "invalid token,wrong issuer",
			audience: "test/audience",
			issuer:   "issuer",
			header: http.Header{
				"X-Goog-IAP-JWT-Assertion": {"token"},
			},
			payload: &idtoken.Payload{
				Issuer:   "issuer-wrong",
				Audience: "test/audience",
				Expires:  0,
				IssuedAt: 0,
			},
			err:        nil,
			statusCode: 403,
		},
		{
			desc:     "invalid token,wrong audience",
			issuer:   "dummy-issuer",
			audience: "test/audience",
			header: http.Header{
				"X-Goog-IAP-JWT-Assertion": {"token"},
			},
			payload: &idtoken.Payload{
				Issuer:   "dummy-issuer",
				Audience: "test/audience-wrong",
				Expires:  0,
				IssuedAt: 0,
			},
			err:        nil,
			statusCode: 403,
		},
		{
			desc:     "invalid token,expired",
			issuer:   "dummy-issuer",
			audience: "test/audience",
			header: http.Header{
				"X-Goog-IAP-JWT-Assertion": {"token"},
			},
			payload: &idtoken.Payload{
				Issuer:   "dummy-issuer",
				Audience: "test/audience",
				Expires:  time.Now().Unix() - 300,
				IssuedAt: time.Now().Unix() - 300,
			},
			err:        nil,
			statusCode: 403,
		},
		{
			desc:     "invalid token,future",
			issuer:   "dummy-issuer",
			audience: "test/audience",
			header: http.Header{
				"X-Goog-IAP-JWT-Assertion": {"token"},
			},
			payload: &idtoken.Payload{
				Issuer:   "dummy-issuer",
				Audience: "test/audience",
				Expires:  time.Now().Unix() + 600,
				IssuedAt: time.Now().Unix() + 300,
			},
			err:        nil,
			statusCode: 403,
		},
		{
			desc:     "token validation error",
			issuer:   "dummy-issuer",
			audience: "test/audience",
			header: http.Header{
				"X-Goog-IAP-JWT-Assertion": {"token"},
			},
			err:        fmt.Errorf("validaton error"),
			statusCode: 403,
		},
		{
			desc:     "null payload and no error",
			issuer:   "dummy-issuer",
			audience: "test/audience",
			header: http.Header{
				"X-Goog-IAP-JWT-Assertion": {"token"},
			},
			payload:    nil,
			err:        nil,
			statusCode: 403,
		},
	}

	for _, tc := range testCases {
		// DO NOT run this parallel
		t.Run(tc.desc, func(t *testing.T) {
			jwtValidator = fakeTokenValidator{
				payload: tc.payload,
				err:     tc.err,
			}

			audience = tc.audience
			issuer = tc.issuer

			// convert the request headers to canonical mime
			// it will save you many hours of WHY the header is not found
			reqHeader := http.Header{}
			for k, v := range tc.header {
				reqHeader[textproto.CanonicalMIMEHeaderKey(k)] = v
			}

			req := &http.Request{
				Header: reqHeader,
			}

			w := &fakeResponseWriter{
				header: http.Header{},
			}

			validateJWT(w, req)
			if tc.statusCode != w.statusCode {
				t.Errorf("%v: expected status %d, got %d", tc.desc,
					tc.statusCode,
					w.statusCode)
			}
		})
	}

}

// fakes space

type fakeProjectsAPIService struct {
	project *cloudresourcemanager.Project
	err     error
}

func (fake fakeProjectsAPIService) Get(project string) (*cloudresourcemanager.Project, error) {
	return fake.project, fake.err
}

type fakeBackendsAPIService struct {
	backends []*compute.BackendService
	err      error
}

func (fake fakeBackendsAPIService) List(filter string) ([]*compute.BackendService, error) {
	// TODO: add more sophisticated filter strategy
	switch filter {
	case "iap.enabled=true":
		filtered := []*compute.BackendService{}
		for _, v := range fake.backends {
			if v.Iap != nil && v.Iap.Enabled {
				filtered = append(filtered, v)
			}
		}
		return filtered, fake.err
	default:
		return fake.backends, fake.err
	}
}

type fakeTokenValidator struct {
	payload *idtoken.Payload
	err     error
}

func (g fakeTokenValidator) Validate(ctx context.Context, idToken string, audience string) (*idtoken.Payload, error) {
	return g.payload, g.err
}

type fakeResponseWriter struct {
	header     http.Header
	statusCode int
	bytes      []byte
}

func (w *fakeResponseWriter) Header() http.Header {
	return w.header
}

func (w *fakeResponseWriter) Write(p []byte) (int, error) {
	w.bytes = p
	return len(p), nil
}

func (w *fakeResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}
