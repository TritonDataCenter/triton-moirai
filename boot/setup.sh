#!/bin/bash

#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

#
# Copyright 2025 MNX Cloud, Inc.
#

set -o errexit
set -o pipefail
set -o xtrace

if [[ -f /lib/svc/share/smf_include.sh ]]; then
    # shellcheck disable=SC1091
    source /lib/svc/share/smf_include.sh
fi

if [[ -f /var/tmp/.first-boot-done ]]; then
    exit "${SMF_EXIT_NODAEMON:?}"
fi

if ! mdata-get cloud.tritoncompute:loadbalancer | grep -w -q true; then
    printf 'Metadata key cloud.tritoncompute:loadbalancer does not indicate load balancer\n'
    exit "${SMF_EXIT_ERR_FATAL:?}"
fi


cron_jobs=(
    '* * * * * /opt/triton/clb/reconfigure'
)

function fatal {
    echo "$*" >&2
    exit 1
}

function setup_crontab {
    cron_tmp="$(mktemp /tmp/cron.XXXXXX)"
    crontab -l  > "${cron_tmp}"
    printf '%s\n' "${cron_jobs[@]}" >> "${cron_tmp}"
    crontab "${cron_tmp}"
    rm -f "${cron_tmp}"
}

function setup_haproxy_logs {
    #rsyslog was already set up by common setup- this will overwrite the
    # config and restart since we want haproxy to log locally.

    echo "Updating /etc/rsyslog.conf"
    mkdir -p /var/tmp/rsyslog/work
    chmod 777 /var/tmp/rsyslog/work

    cat > /etc/rsyslog.conf <<"HERE"
$MaxMessageSize 64k

$ModLoad immark
$ModLoad imsolaris
$ModLoad imudp

*.err;kern.notice;auth.notice                   /dev/sysmsg
*.err;kern.debug;daemon.notice;mail.crit        /var/adm/messages

*.alert;kern.err;daemon.err                     operator
*.alert                                         root

*.emerg                                         *

mail.debug                                      /var/log/syslog

auth.info                                       /var/log/auth.log
mail.info                                       /var/log/postfix.log

$WorkDirectory /var/tmp/rsyslog/work
$ActionQueueType Direct
$ActionQueueFileName sdcfwd
$ActionResumeRetryCount -1
$ActionQueueSaveOnShutdown on

local0.* /var/log/haproxy.log

$UDPServerAddress 127.0.0.1
$UDPServerRun 514
HERE


    svcadm restart system-log || fatal "Unable to restart rsyslog"

    logadm -w /var/log/haproxy.log -C 5 -c -s 100m
}

setup_haproxy_logs

# Register dhydrated account
/opt/triton/dehydrated/dehydrated --register --accept-terms
svccfg import /opt/local/lib/svc/manifest/haproxy.xml

# Run immediately to prep the system.
RUST_LOG=debug /opt/triton/clb/reconfigure

setup_crontab
touch /var/tmp/.first-boot-done

exit "${SMF_EXIT_NODAEMON}"
