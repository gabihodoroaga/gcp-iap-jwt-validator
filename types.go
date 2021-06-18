package main

import (
	"context"

	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/idtoken"
)

type searchOptions struct {
	projectID            string
	oauthClientID        string
	serviceName          string
	serviceGkeNamespace  string
	serviceGkeName       string
	serviceGkePortName   string
	serviceGkePortNumber int
}

type serviceDescription struct {
	ServiceName string
	ServicePort serviceBackendPort
}

type serviceBackendPort struct {
	Name   string
	Number int
}

type projectsAPIService interface {
	Get(project string) (*cloudresourcemanager.Project, error)
}

type backendsAPIService interface {
	List(filter string) ([]*compute.BackendService, error)
}

// gcpProjectsAPIService is a thin wrapper around google api so it can
// be easily mocker for testing
type gcpProjectsAPIService struct {
	projectsService *cloudresourcemanager.ProjectsService
}

func (gcp gcpProjectsAPIService) Get(project string) (*cloudresourcemanager.Project, error) {
	return gcp.projectsService.Get(project).Do()
}

// gcpBackendsAPIService is a thin wrapper around google api so it can
// be easily mocked for testing
type gcpBackendsAPIService struct {
	backendServicesService *compute.BackendServicesService
}

func (gcp gcpBackendsAPIService) List(filter string) ([]*compute.BackendService, error) {
	backends, err := gcp.backendServicesService.List(searchOpt.projectID).Filter("iap.enabled=true").Do()
	if err != nil {
		return nil, err
	}
	return backends.Items, nil
}

type tokenValidator interface {
	Validate(ctx context.Context, idToken string, audience string) (*idtoken.Payload, error)
}

// gcpTokenValidator is wrapper around idtoken.Validate so it can be mocked
// for testing
type gcpTokenValidator struct {
}

func (g gcpTokenValidator) Validate(ctx context.Context, idToken string, audience string) (*idtoken.Payload, error) {
	return idtoken.Validate(ctx, idToken, audience)
}
