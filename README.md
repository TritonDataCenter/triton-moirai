<!--
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
-->

<!--
    Copyright 2025 MNX Cloud, Inc.
-->

# triton-moirai

This repository is part of the Triton Data Center project. See the [contribution
guidelines](https://github.com/TritonDataCenter/triton/blob/master/CONTRIBUTING.md)
and general documentation at the main
[Triton project](https://github.com/TritonDataCenter/triton) page.

Moirai is an HAProxy based load balancer for Triton.

## Features

* Automatic certificate generation via [triton-dehydrated][1]
* Automatic configuration of backends

[1]: https://github.com/TritonDataCenter/triton-dehydrated

## Backend configuration

Moirai supports the following keys:

* `cloud.tritoncompute:loadbalancer` - This must be set to `true` and will be
   used by node-triton and/or CloudAPI at a later date.
* `cloud.tritoncompute:portmap` - This configures the listening ports to
  backend mappings. This is comma separated list of service designations.
  See below for service designation syntax.
* `cloud.tritoncompute:max_rs` - By default up to 32 backend servers are
  supported. If you need to scale larger than 32 backend instances, set this
  to the desired value.
* `cloud.tritoncompute:certificate_name` - Comma separated list of certificate
  subjects. The first in the list will be the subject `CN`. The rest of the
  names will be Subject Alternate Names (SAN).
* `cloud.tritoncompute:metrics_acl` - Space or comma-separated list of IP prefixes
  (e.g., `198.51.100.0/24`) that are allowed to access the metrics endpoint.
* `cloud.tritoncompute:metrics_port` - Port number for the metrics endpoint.
  Defaults to `8405` if not specified.

Metadata keys can be added post-provision. The load balancer will reconfigure
itself shortly after the metadata is updated.

All other metadata keys used by Triton are also supported (e.g.,
`triton.cns.services`, `tritoncli.ssh.proxy`, etc.).

## Service Designations

The `cloud.tritoncompute:portmap` metadata key is a list of service designations
separated by commas or spaces.

A service designation uses the following syntax:

```
<type>://<listen port>:<backend name>[:<backend port>][{health check params}]
```

* `type` - Must be one of `http`, `https`, `https+insecure`, `https-http`, or `tcp`:
  * `http` - Configures a Layer-7 proxy using the HTTP protocol. The backend
    server(s) must not use SSL/TLS. `X-Forwarded-For` header will be added to
    requests.
  * `https` - Configures a Layer-7 proxy using the HTTP protocol. The backend
    server(s) must use SSL/TLS. The backend certificate WILL be verified.
    The front end services will use a certificate issued by Let's Encrypt if
    the `cloud.tritoncompute:certificate_name` metadata key is also provided.
    Otherwise, a self-signed certificate will be generated. `X-Forwarded-For`
    header will be added to requests.
  * `https+insecure` - Configures a Layer-7 proxy using the HTTP protocol. The backend
    server(s) must use SSL/TLS. The backend certificate will NOT be verified.
    The front end services will use a certificate issued by Let's Encrypt if
    the `cloud.tritoncompute:certificate_name` metadata key is also provided.
    Otherwise, a self-signed certificate will be generated. `X-Forwarded-For`
    header will be added to requests.
  * `https-http` - Configures a Layer-7 proxy using the HTTP protocol. The backend
    server(s) must NOT use SSL/TLS.
    The front end services will use a certificate issued by Let's Encrypt if
    the `cloud.tritoncompute:certificate_name` metadata key is also provided.
    Otherwise, a self-signed certificate will be generated. `X-Forwarded-For`
    header will be added to requests.
  * `tcp` - Configures a Layer-4 proxy. The backend can use any port. If SSL/TLS
    is desired, the backend must configure its own certificate.
* `listen port` - This designates the front end listening port.
* `backend name` - This is a DNS name that must be resolvable. This **SHOULD**
  be a CNS name, but can be any fully qualified DNS domain name.
* `backend port` - Optional. This designates the back end port that servers will
  be listening on. If provided, the back end will be configured to use A record
  lookups. If not provided, the back end will be configured to use SRV
  record lookup.
* `health check params` - Optional. JSON-like syntax for configuring health checks
  (see Health Check Configuration section below).

### Health Check Configuration

Health checks can be configured using a JSON-like syntax appended to service designations. The parameters are enclosed in curly braces `{}` and use comma-separated key:value pairs.

#### Supported Parameters

* `check` - HTTP endpoint path for health checks (e.g., `/healthz`, `/status`, `/ping`)
* `port` - Port number for health check requests (overrides the backend port)
* `rise` - Number of consecutive successful checks before marking server as healthy (default: HAProxy default)
* `fall` - Number of consecutive failed checks before marking server as unhealthy (default: HAProxy default)

#### Health Check Syntax

```
{check:/endpoint,port:9000,rise:2,fall:1}
```

All parameters are optional and can be specified in any order. If `port` is not specified, health checks will use the same port as the backend service.

#### Health Check Examples

```
# HTTP service with health check on same port
http://80:web.example.com:8080{check:/healthz}

# HTTPS service with health check on different port
https://443:api.example.com:8443{check:/status,port:9000}

# TCP service with health check parameters
tcp://3306:db.example.com:3306{check:/ping,rise:3,fall:2}

# Service with all health check parameters
http://80:app.example.com:8080{check:/health,port:8081,rise:5,fall:2}
```

### Basic Service Examples

```
# Basic HTTP service
http://80:my-backend.svc.my-login.us-west-1.cns.example.com:80

# Basic HTTPS service
https://443:my-backend.svc.my-login.us-west-1.cns.example.com:8443

# Basic TCP service (using SRV records)
tcp://636:my-backend.svc.my-login.us-west-1.cns.example.com

# HTTP service with health check
http://80:my-backend.svc.my-login.us-west-1.cns.example.com:80{check:/healthz}

# HTTPS service with comprehensive health check configuration
https://443:my-backend.svc.my-login.us-west-1.cns.example.com:8443{check:/status,port:9000,rise:3,fall:1}
```

## Certificate setup

In order to properly generate a certificate you must have DNS CNAME records
pointing to the load balancer instance's CNS records. See the
[`triton-dehydrated`][2] documentation for how to properly configure this.

[2]: https://github.com/TritonDataCenter/triton-dehydrated?tab=readme-ov-file#how-to-use-inside-a-user-container-on-triton

If no certificate name is provided in the metadata, a self-signed certificate will be
generated automatically.

## Metrics polling

If the `cloud.tritoncompute:metrics_acl` metadata key is not empty then the
metrics endpoint will be enabled. The ACL must be an IP prefix
(e.g., `198.51.100.0/24`). Multiple comma or space separated prefixes can be
included.

The metrics endpoint listens on port `8405` by default. This can be customized
by setting the `cloud.tritoncompute:metrics_port` metadata key to a different
port number (must be between 1-65534).

**Note:** The load balancer will respond to *all hosts* on the metrics port. Hosts
outside of the configured ACL will receive a `403` response. If you want the
load balancer to not respond at all then you must also configure Cloud Firewall
for the instance.

## Notes

* Once a named certificate is used, the load balancer instance can't go back to
  a self-signed certificate. Continue to use the expired certificate or
  deploy a replacement loadbalancer.
* The maximum number of backend servers is configurable from 32 up to 1024.
* The application includes failsafes to prevent invalid configurations from being applied.

## Development

### Code Structure

- `src/lib.rs` - Contains core functionality, data structures, and helper functions
- `src/certificates.rs` - TLS certificate management module
- `src/reconfigure.rs` - Main application entry point (replaces the original `reconfigure` bash script)

### Quick Start

```bash
# Clone the repository
git clone git@github.com:TritonDataCenter/triton-moirai.git
cd triton-moirai

# Build the project
cargo build

# Run tests
cargo test

# Build for production
cargo build --release
```
### LetsEncrypt Testing

If you need to do a lot of iteration on the dehydrated LetsEncrypt integration
you can add a couple of lines to `dehydrated.cfg` to point it at the staging endpoint:

```
CA=letsencrypt-test
PREFERRED_CHAIN='(STAGING) Pretend Pear X1'
```

## Verification Testing

### Importing a Jenkins build

On the headnode:
```bash
sdc-imgadm import -S https://updates.tritondatacenter.com?channel=experimental ${JENKINS_BUILD_UUID?}
```

### Basic Setup (Backend Instances)

```bash
# Get your account UUID for CNS names
UUID=$(triton account get | awk '/^id:/{print $2}')
CNS_DOMAIN=us-central-1.cns.mnx.io
REAL_DOMAIN=example.com
IMAGE=cloud-load-balancer
PACKAGE=g1.nano

# Create Backends
triton instance create -t triton.cns.services=web base-64-trunk ${PACKAGE?}
triton instance create -t triton.cns.services=web base-64-trunk ${PACKAGE?}

# Configure Backends
triton instance list -H tag.triton.cns.services=web -o shortid | while read host; do triton ssh $host "pkgin -y in nginx && svcadm enable nginx && hostname > /opt/local/share/examples/nginx/html/hostname.txt && curl http://localhost/hostname.txt" ; done;
```

### HTTP Only (No TLS)

```bash
# Create Loadbalancer with plain HTTP
triton instance create -w -t triton.cns.services=frontend-plain \
  -m cloud.tritoncompute:portmap=http://80:web.svc.${UUID?}.${CNS_DOMAIN?}:80 \
  -m cloud.tritoncompute:loadbalancer=true \
  -n frontend-plain \
  ${IMAGE?} ${PACKAGE?}

# Test the load balancer
curl http://frontend-plain.svc.${UUID?}.${CNS_DOMAIN?}/hostname.txt
```

### HTTPS with Self-Signed Certificate

```bash
# Create Loadbalancer with HTTPS but no certificate_name (will use self-signed)
triton instance create -w -t triton.cns.services=frontend-ssl \
  -m cloud.tritoncompute:portmap=https-http://443:web.svc.${UUID?}.${CNS_DOMAIN?}:80 \
  -m cloud.tritoncompute:loadbalancer=true \
  -n frontend-ssl \
  ${IMAGE?} ${PACKAGE?}

# Test the load balancer (will use self-signed certificate)
curl -k https://frontend-ssl.svc.${UUID?}.${CNS_DOMAIN?}/hostname.txt
```

### HTTPS with LetsEncrypt Certificate

This test exercise all three flavors of https proxy (http backend, unverified https, verified https):

```bash
# Create Loadbalancer with HTTPS and LetsEncrypt certificate
# Note: You must have proper DNS CNAME records pointing to the load balancer's CNS record
triton instance create -w -t triton.cns.services=frontend \
  -m cloud.tritoncompute:portmap="https-http://443:web.svc.${UUID?}.${CNS_DOMAIN?}:80,https+insecure://8443:frontend-ssl.svc.${UUID?}.${CNS_DOMAIN?}:443,https://9443:us-central.manta.mnx.io:443" \
  -m cloud.tritoncompute:certificate_name=${REAL_DOMAIN?} \
  -m cloud.tritoncompute:loadbalancer=true \
  -n frontend \
  ${IMAGE?} ${PACKAGE?}

# Test the load balancer (will use LetsEncrypt certificate)
curl https://${REAL_DOMAIN?}/hostname.txt
curl https://${REAL_DOMAIN?}:8443/hostname.txt
curl https://${REAL_DOMAIN?}:9443/nshalman/public/hello-world.txt
```

### TCP Load Balancing with HTTP Health Checks

```bash
# Create TCP load balancer (Layer-4 proxy)
triton instance create -w -t triton.cns.services=frontend-tcp \
  -m cloud.tritoncompute:portmap="tcp://80:web.svc.${UUID?}.${CNS_DOMAIN?}:80{check:/hostname.txt,rise:2,fall:1}" \
  -m cloud.tritoncompute:loadbalancer=true \
  -n frontend-tcp \
  ${IMAGE?} ${PACKAGE?}

# Test the TCP load balancer
curl http://frontend-tcp.svc.${UUID?}.${CNS_DOMAIN?}/hostname.txt
```

### Important Notes for Testing

1. **DNS Configuration**: For LetsEncrypt certificates, ensure you have proper DNS CNAME records pointing to your load balancer's CNS record before creating the instance.

2. **Certificate Names**: Replace `example.com` with your actual domain name when testing LetsEncrypt certificates.

3. **CNS Names**: The `${UUID?}` variable is automatically populated from your account information.

4. **Self-Signed Certificates**: Use the `-k` flag with curl when testing self-signed certificates to skip certificate verification.
