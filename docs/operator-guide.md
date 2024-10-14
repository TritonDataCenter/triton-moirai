---
title: Cloud Load Balancer
markdown2extras: tables, code-friendly, cuddled-lists, fenced-code-blocks
---
<!--
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
-->
<!--
    Copyright 2024 MNX Cloud, Inc.
-->

## Introduction

CLB currently runs entirely tenant side, as an appliance instance. Because of
this, there's very little that Triton operators need to do to manage it beyond
making it available to tenants.

## Providing CLB to Triton Accounts

The cloud-load-balancer image is availabie from the Triton Updates server
(<https://updates.tritondatacenter.com>) rather than the SmartOS image server
(<https://images.smartos.org>) and is based on the `triton-origin-image` used
by all Triton services. But unlike other services,CLB does not run as a Triton
service and is not (currently) managed by sdcadm.

Instead, operators will need to manually import the image and make it available
to tenants.

Note: The experimental channel is used here as an example, but you should use
the channel most appropriate for your Triton installation. In most cases this
will be `release` or `support`. If you are unsure why you're choosing `dev` or
`experimental`, then do not use those channels.

<!-- markdownlint-disable line-length -->

```term
[root@headnode (us-demo-1) ~]# updates-imgadm list -C experimental --latest name=cloud-load-balancer
UUID                                  NAME                 VERSION                         FLAGS  OS       PUBLISHED
8605a524-0655-43b9-adf1-7d572fe797eb  cloud-load-balancer  PR-1-20241012T022846Z-gb0dcbea  I      smartos  2024-10-12T02:29:07Z
[root@headnode (us-demo-1) ~]# sdc-imgadm import -S https://updates.tritondatacenter.com?channel=experimental 8605a524-0655-43b9-adf1-7d572fe797eb
Imported image 8605a524-0655-43b9-adf1-7d572fe797eb (cloud-load-balancer, PR-1-20241012T022846Z-gb0dcbea, state=active)
```

<!-- markdownlint-enable line-length -->

### Allow a Subset of Accounts

Once the image is imported, it is initially set `private`, owned by the `admin`
account, and unavailable to all other accounts.

To make the image available to a subset of accounts, add each account UUID to
the image ACL.

<!-- markdownlint-disable line-length -->

```term
[root@headnode (us-demo-1) ~]# sdc-imgadm get 8605a524-0655-43b9-adf1-7d572fe797eb | json public acl
false
[root@headnode (us-demo-1) ~]# sdc-imgadm add-acl 8605a524-0655-43b9-adf1-7d572fe797eb cc1e7a97-0d4e-44c4-ac2c-e73e5c7d35f8
Updated ACL for image 8605a524-0655-43b9-adf1-7d572fe797eb
[root@headnode (us-demo-1) ~]# sdc-imgadm get 8605a524-0655-43b9-adf1-7d572fe797eb | json public acl
false
[
  "cc1e7a97-0d4e-44c4-ac2c-e73e5c7d35f8"
]
```

<!-- markdownlint-enable line-length -->

### Allow All Accounts

To make the image available to all accounts, make the image public.

<!-- markdownlint-disable line-length -->

```term
[root@headnode (us-demo-1) ~]# sdc-imgadm get 8605a524-0655-43b9-adf1-7d572fe797eb | json public
false
[root@headnode (us-demo-1) ~]# sdc-imgadm update 8605a524-0655-43b9-adf1-7d572fe797eb public=true
Update image 8605a524-0655-43b9-adf1-7d572fe797eb (cloud-load-balancer, PR-1-20241012T022846Z-gb0dcbea, state=active)
[root@headnode (us-demo-1) ~]# sdc-imgadm get 8605a524-0655-43b9-adf1-7d572fe797eb | json public
true
```

<!-- markdownlint-enable line-length -->

Once the image is made available to accounts, either via acl or being public,
users will see it immediately.

<!-- markdownlint-disable line-length -->

```term
$ triton -p demo images type=zone-dataset
SHORTID   NAME                 VERSION                         FLAGS  OS       TYPE          PUBDATE
85d0f826  base-64-lts          21.4.1                          P      smartos  zone-dataset  2022-07-11
93bdf06a  base-64-lts          20.4.1                          P      smartos  zone-dataset  2022-07-12
e44ed3e0  base-64-lts          22.4.0                          P      smartos  zone-dataset  2023-01-10
8adac45a  base-64-lts          23.4.0                          P      smartos  zone-dataset  2024-01-06
8605a524  cloud-load-balancer  PR-1-20241012T022846Z-gb0dcbea  IP     smartos  zone-dataset  2024-10-12
```

<!-- markdownlint-enable line-length -->
