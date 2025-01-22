#!/usr/bin/env node --abort-on-uncaught-exception

/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2024 MNX Cloud, Inc.
 */


var child_process = require('child_process');
var os = require('os');
var process = require('process');

var VALID_PROTOCOLS = [
    'tcp',
    'http',
    'https'
];

var MAX_PORT = 65534;
var MIN_PORT = 1;
var MAX_BACKENDS_LOW = 32;
var MAX_BACKENDS_HIGH = 1024;
var STICKY_MODES = [
    'http',
    'https'
];

var dbg = function (x) {
    console.error(JSON.stringify(x, null, 2));
};

var mdataGet = function (key, callback) {
    // assert.string(key, 'key');
    // assert.func(callback, 'callback');

    var md_cmd = os.platform() === 'sunos' ? '/usr/sbin/mdata-get' :
        process.cwd() + '/tools/mock-mdata-get';

    // child_process.execFile('/usr/sbin/mdata-get', [
    child_process.execFile(md_cmd, [
        key
    ], function _onMdata(err, stdout, stderr) {
        // assert.ifError(err, 'mdata-get should always work');
        if (err || stderr) {
            // mdata-get error means key was not found. We don't care.
        }
        callback(stdout.trim());
    });
};

var parseService = function (svcStr, r) {
    var m = svcStr.match(/([A-z]+):\/\/([0-9]+):(.*)/);
    if (m) {
        var b = m[3].split(':');
        var svcObj = {
            string: m[0].toLowerCase(),
            proto: m[1].toLowerCase(),
            listen: parseInt(m[2], 10),
            backend: {
                name: b[0].toLowerCase(),
                port: parseInt(b[1], 10)
            }
        };
        return svcObj;
    }
    r.push({string: svcStr, errors: ['Unparsable chunk']});
    return false;
};

mdataGet('cloud.tritoncompute:portmap', function (s) {
    dbg({mDataString: s});
    var removed = [];
    var services = s.split(/[, ]/)
                    .map(function (x) {
                        return parseService(x, removed);
                    })
                    .filter(function (x) {
                        // Filter out null results from non-matches
                        if (x) {
                            return x;
                        }
                        return false;
                    });

    // Validate fields of matcing objects.
    services = services.filter(function (x) {
        var errs = [];

        if (VALID_PROTOCOLS.indexOf(x.proto) === -1) {
            errs.push('Unsupported proto: ' + x.proto);
        }

        if (isNaN(x.listen) || MAX_PORT < x.listen || x.listen < MIN_PORT) {
            errs.push('Listen port is invalid: ' + x.listen);
        }

        if (x.backend.hasOwnProperty('port') &&
            (MAX_PORT < x.backend.port || x.backend.port < MIN_PORT)) {
            errs.push('Backend port is invalid: ' + x.backend.port);
        }

        // Filter out if there are any errors.
        if (errs.length > 0) {
            removed.push({string: x.string, errors: errs});
            return false;
        }
        return true;
    });
    dbg({ ignored: removed});
    dbg({ validServices: services});
    mdataGet('cloud.tritoncompute:max_rs', function (rs) {
        var max_rs = parseInt(rs, 10);
        if (isNaN(max_rs)) {
            max_rs = MAX_BACKENDS_LOW;
        }
        // Must be at least the low watermark
        max_rs = Math.max(max_rs, MAX_BACKENDS_LOW);
        // Must be at most the high watermark
        max_rs = Math.min(max_rs, MAX_BACKENDS_HIGH);


        services.forEach(function (x, i) {
            var bind = '\tbind *:' + x.listen;
            var backend_ssl = '';
            if (x.proto === 'https') {
                bind += ' ssl crt /opt/triton/ssl/default/fullchain.pem';
                backend_ssl = ' ssl verify none';
            }
            var fe = [
                'frontend fe' + i,
                '\tmode ' + x.proto,
                bind,
                '\tdefault_backend be' + i
            ];
            console.log(fe.join('\n') + '\n');

            var backend_port = '';
            var sticky_cookie = '';
            if (!isNaN(x.backend.port)) {
                backend_port = ':' + x.backend.port;
            }
            if (STICKY_MODES.indexOf(x.proto) !== -1) {
                sticky_cookie = [
                    '\tcookie CLOUD-TRITONCOMPUTE-RS insert indirect ' +
                        'nocache dynamic\n',
                    '\tdynamic-cookie-key mysecretphrase\n'
                ].join('');
            }
            var be = [
                'backend be' + i + '\n',
                '\tmode ' + x.proto + '\n',
                sticky_cookie,
                '\tserver-template rs ' + max_rs + ' ',
                x.backend.name + backend_port,
                backend_ssl,
                ' check resolvers system init-addr none',
                '\n'
            ];
            // amazon.com:80 check resolvers system init-addr none'

            console.log(be.join(''));
            // generate frontend and backend configurations here
        });
    });
});
