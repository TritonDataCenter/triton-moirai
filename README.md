<!--
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
-->

<!--
    Copyright 2024 MNX Cloud, Inc.
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

Metadata keys can be added post-provision. The load balancer will reconfigure
itself shortly after the metadata is updated.

All other metadata keys used by Triton are also supported (e.g.,
`triton.cns.services`, `tritoncli.ssh.proxy`, etc.).

## Service Designations

The `cloud.tritoncompute:portmap` metadata key is a list of service designations
separated by commas or spaces.

A service designation uses the following syntax:

    <type>://<listen port>:<backend name>[:<backend port>]

* `type` - Must be one of `http`, `https`, or `tcp`.
  * `http` - Configures a Layer-7 proxy using the HTTP protocol. The backend
    server(s) must not use SSL/TLS. `X-Forwarded-For` header will be added to
    requests.
  * `https` - Configures a Layer-7 proxy using the HTTP protocol. The backend
    server(s) must use SSL/TLS. The backend certficate will not be verified. The
    front end services will use a certificate issued by Let's Encrypt if
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
  lookups. If a not provided then the back end will be configured to use SRV
  record lookup.

Examples:

    http://80:my-backend.svc.my-login.us-west-1.cns.example.com:80
    https://443:my-backend.svc.my-login.us-west-1.cns.example.com:8443
    tcp://636:my-backend.svc.my-login.us-west-1.cns.example.com

## Certificate setup

In order to properly generate a certificate you must have DNS CNAME records
pointing to the load balancer instance's CNS records. See the
[`triton-dehydrated`][2] documentation for how to properly configure this.

[2]: https://github.com/TritonDataCenter/triton-dehydrated?tab=readme-ov-file#how-to-use-inside-a-user-container-on-triton

## Development

Typically development is done by:

* making edits to a clone of triton-moirai.git on a Mac (likely Linux too, but
  that's untested) or a SmartOS development zone,

        git clone git@github.com:TritonDataCenter/triton-moirai.git
        cd triton-moirai
        git submodule update --init   # not necessary first time
        vi

* building:

        make all
        make check

* then testing changes.

## Notes

* Once a named certificate is used, the load balancer instance can't go back to
  a self-signed certificate. Continue to use the expired certificate or
  deploy a replacement loadbalancer.

## Testing

* Prerequisites:
  * Set up fabrics on the Triton deployment.
  * Ensure there are no existing NAT zones provisioned.
  * Execute `sdcadm post-setup dev-headnode-prov`.

* To sync local changes to a running COAL and run the test suite there use:

    make test-coal

* To run tests while logged into a running VMAPI instance:

    /opt/smartdc/vmapi/test/runtests
