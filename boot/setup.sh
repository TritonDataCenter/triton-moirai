#!/bin/bash

#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

#
# Copyright 2024 MNX Cloud, Inc.
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
    exit 1
fi

cert_name=$(./mdata-get cloud.tritoncompute:certificate_name)

cron_jobs=(
    '16 1 * * * /opt/triton/dehydrated/dehydrated -c 2>&1 >> /var/log/triton-dehydrated.log'
    '* * * * * /opt/triton/lb/genconfig'
)

function fatal {
    echo "$*" >&2
    exit 1
}

function create_crontab_entries {
    cron_tmp="$(mktemp)"
    crontab -l  > "${cron_tmp:?}"
    printf '%s\n' "${cron_jobs[@]}" >> "${cron_tmp:?}"
    crontab "${cron_tmp:?}"
    rm -f "${cron_tmp:?}"
}

function setup_haproxy_rsyslogd {
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

function setup_tls_certificate() {
    if [[ -f ${self_signed_dir}/privkey.pem && \
          -f ${self_signed_dir}/cert.pem ]]; then
        echo "TLS Certificate Exists"
    else
        echo "Generating TLS Self-signed Certificate"
        mkdir -p ${self_signed_dir}
        /opt/local/bin/openssl req -x509 -nodes -subj '/CN=*' \
            -pkeyopt ec_paramgen_curve:prime256v1 \
            -pkeyopt ec_param_enc:named_curve \
            -newkey ec -keyout ${self_signed_dir}/privkey.pem \
            -out ${self_signed_dir}/cert.pem -days 3650
        cat ${self_signed_dir}/privkey.pem >> ${self_signed_dir}/cert.pem
    fi
}


if [[ -n "$cert_name" ]]; then
    cd /opt/triton/dehydrated
    mdata-get cloud.tritoncompute:certificate_name > domains.txt
    ./dehydrated --register --accept-terms
    ./dehydrated -c

    tmp=$(mktemp)
    crontab -l > "$tmp"
    create_crontab_entries
else
    echo 'No certificate name present. Generating self-signed.'
    self_signed_dir=/opt/triton/ssl/self-signed
    setup_tls_certificate
    cd /opt/triton/ssl
    ln -s self-signed default
    cd self-signed
    openssl ecparam -out privkey.pem -name prime256v1 -genkey
    openssl req -new -days 3650 -nodes -x509 \
        -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com" \
        -key privkey.pem -out cert.pem
    ln -s cert.pem chain.pem
    ln -s chain.pem fullchain.pem
fi

setup_haproxy_rsyslogd

touch /var/tmp/.first-boot-done

exit "${SMF_EXIT_NODAEMON}"
