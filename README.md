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
  (e.g., `198.51.100.0/24`) that are allowed to access the metrics endpoint on port `8405`.

Metadata keys can be added post-provision. The load balancer will reconfigure
itself shortly after the metadata is updated.

All other metadata keys used by Triton are also supported (e.g.,
`triton.cns.services`, `tritoncli.ssh.proxy`, etc.).

## Service Designations

The `cloud.tritoncompute:portmap` metadata key is a list of service designations
separated by commas or spaces.

A service designation uses the following syntax:

```
<type>://<listen port>:<backend name>[:<backend port>]
```

* `type` - Must be one of `http`, `https`, `httpss`, or `tcp`:
  * `http` - Configures a Layer-7 proxy using the HTTP protocol. The backend
    server(s) must not use SSL/TLS. `X-Forwarded-For` header will be added to
    requests.
  * `https` - Configures a Layer-7 proxy using the HTTP protocol. The backend
    server(s) must NOT use SSL/TLS.
    The front end services will use a certificate issued by Let's Encrypt if
    the `cloud.tritoncompute:certificate_name` metadata key is also provided.
    Otherwise, a self-signed certificate will be generated. `X-Forwarded-For`
    header will be added to requests.
  * `httpss` - Configures a Layer-7 proxy using the HTTP protocol. The backend
    server(s) must use SSL/TLS. The backend certificate will not be verified.
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

### Examples

```
http://80:my-backend.svc.my-login.us-west-1.cns.example.com:80
https://443:my-backend.svc.my-login.us-west-1.cns.example.com:8443
tcp://636:my-backend.svc.my-login.us-west-1.cns.example.com
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
metrics endpoint will be enabled on port `8405`. The ACL must be an IP prefix
(e.g., `198.51.100.0/24`). Multiple comma or space separated prefixes can be
included.

If the `cloud.tritoncompute:certificate_name` key is supplied then the metrics
endpoint will be served via HTTPS. If the key is not supplied then the metrics
endpoint will be served via HTTP.

**Note:** The load balancer will respond to *all hosts* on port `8405`. Hosts
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

## Smoke Testing

```
# Create Backends
triton instance create -t triton.cns.services=web base-64-trunk g1.nano
triton instance create -t triton.cns.services=web base-64-trunk g1.nano

# Configure Backends
triton instance list -H tag.triton.cns.services=web -o shortid | while read host; do triton ssh $host "pkgin -y in nginx && svcadm enable nginx && hostname > /opt/local/share/examples/nginx/html/hostname.txt && curl http://localhost/hostname.txt"& done;

# Create Loadbalancer
triton instance create -t triton.cns.services=frontend -m cloud.tritoncompute:portmap=tcp://80:web.svc.e50784dc-5b87-4f05-8487-f04c16b7d729.us-central-1.cns.mnx.io:80 -m cloud.tritoncompute:loadbalancer=true cloud-load-balancer g1.nano
```
