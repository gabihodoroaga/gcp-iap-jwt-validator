# gcp-iap-jwt-validator

Simple application that can be used to validate if a request originates from IAP (Identity Aware Proxy) on GCP.

You can check this tutorial [hodo.dev] to see how this can be used in GKE.

## How it works

This app is a http server that validated the if the request originates from IAP.

The following steps are performed in order to do the validation:

- search for the authentication header ```X-Goog-IAP-JWT-Assertion```
- if he header is not present returns 401
- if the header exists validates the following:
    - token signature 
    - token issuer - configurable value, defaults to ```https://cloud.google.com/iap```
    - token audience - configurable value
    - token is not expired 
    - token is not emitted in the future
- if one of the above check fails returns 403

### Response codes 

Status code | Description 
----------- | --------------- 
401         | This code is returned when the IAP assertion header is missing from the request 
403         | This code is returned when the token validation fails


### Configuration values

Name                     | Description 
------------------------ | ------------
OAUTH_ISSUER             | The value of the iss field of the jwt token. Default ```https://cloud.google.com/iap```
OAUTH_AUDIENCE           | The value of the aud field of the jwt token.<br>Must have the format: ```/projects/projectNumber/global/backendServices/backendServiceId```<br>If this value is not specified, the app will query the GCP metadata server to search for the audience value using the next configuration values
PROJECT_ID               | The GCP project id
OAUTH_CLIENT_ID          | The OAuth client id configured for the IAP backend
SERVICE_NAME             | The backend service name. The search for the backend will be performed using the ```contains``` function
SERVICE_GKE_NAMESPACE    | The k8s namespace where the service exists. Default: ```default```
SERVICE_GKE_NAME         | The k8s service name. The search for the backend service will be performed using the exact match of SERVICE_GKE_NAMESPACE/SERVICE_GKE_NAME.
SERVICE_GKE_PORT_NAME    | The k8s port name defined in GKE for the backend service
SERVICE_GKE_PORT_NUMBER  | The k8s port number defined in GKE for the backend service


## How to build

```bash
git clone https://github.com/gabihodoroaga/gcp-iap-jwt-validator.git
cd gcp-iap-jwt-validator
env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/ .
docker build -t gabihodoroaga/iap-validator . 
```

## How to use 

This is an example of how to deploy this app as a sidecar and configure nginx to check every request for authorization.

Setup nginx 

```nginx
server {
    listen       80;
    root    /var/www/html/public;
    index   index.html index.htm;

    location / {
        auth_request /auth;
    }
    location = /hc {
        return 200;
    }

    location = /auth { 
        internal;
        proxy_pass              http://127.0.0.1:8081;
        proxy_pass_request_body off;
        proxy_set_header        Content-Length "";
    }
}
```

The ```auth_request``` option tels nginx to send all the requests to the ```/auth``` endpoint and based on the response will allow or reject the request. You can find more about the nginx authorization module from TODO:

Create a ```configmap``` from this file

```bash
kubectl create configmap nginx-config --from-file=nginx.conf
```

In order get he audience value required for the toke validation you need create a service account and to grant view access to the project resources. The permission required are "resourcemanager.projects.get" and 'compute.backendServices.get'

```bash 
# find the project id
PROJECT_ID=`gcloud config list --format 'value(core.project)' 2>/dev/null`
# create the service account
gcloud iam service-accounts create iap-validator-svc \
  --display-name "Service Account for IAP validator sidecar"
# grant user permissions
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
  --member serviceAccount:iap-validator-svs@${PROJECT_ID}.iam.gserviceaccount.com \
  --role roles/browser \
  --role roles/compute.viewer
```

Generate the service account key and save it as kubernetes secret

```bash
gcloud iam service-accounts keys create key.json \
  --iam-account iap-validator-svs@${PROJECT_ID}.iam.gserviceaccount.com
kubectl create secret generic iap-validator-svc-key --from-file=key.json
```

Create a deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:latest
        ports:
        - containerPort: 80
        volumeMounts:
        - name: nginx-config
          mountPath: /etc/nginx/conf.d/default.conf
      - name: iap-validator
        image: gabihodoroaga/iap-validator
        command:
        - /app/iapvalidator
        - -v=1
        env:
        - name: PROJECT_ID
          value: [PROJECT_ID]
        - name: SERVICE_NAME
          value: [SERVICE_NAME]
        - name: GOOGLE_APPLICATION_CREDENTIALS
          value: /var/secrets/google/key.json
        volumeMounts:
        - mountPath: /var/secrets/google
          name: google-cloud-key
      volumes:
      - name: google-cloud-key
        secret:
          secretName: iap-validator-svc-key
    volumes:
      - name: nginx-config
        configMap:
          name: nginx.conf
```

## TODO:

- [ ] benchmark the jwt validation function
- [ ] load test using hey/wrk/bombardier/any load testing tools
