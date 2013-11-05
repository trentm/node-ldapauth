/**
 * Copyright 2013 (c) Trent Mick. All rights reserved.
 * Copyright 2013 (c) Joyent Inc. All rights reserved.
 *
 * LDAP auth.
 *
 * Usage:
 *    var LdapAuth = require('ldapauth');
 *    var auth = new LdapAuth({url: 'ldaps://ldap.example.com:663', ...});
 *
 *    // If you want to be lazier you can skip waiting for 'connect'. :)
 *    // It just means that a quick `.authenticate()` call will likely fail
 *    // while the LDAP connect and bind is still being done.
 *    auth.once('connect', function () {
 *        ...
 *        auth.authenticate(username, password, function (err, user) { ... });
 *        ...
 *        auth.close(function (err) { ... })
 *    });
 */

var p = console.warn;
var EventEmitter = require('events').EventEmitter;
var util = require('util'),
    format = util.format;

var assert = require('assert-plus');
var backoff = require('backoff');
var bcrypt = require('bcrypt');
var ldap = require('ldapjs');
var once = require('once');



//---- internal support stuff

function objCopy(obj) {
    var copy = {};
    Object.keys(obj).forEach(function (k) {
        copy[k] = obj[k];
    });
    return copy;
}

// Other ldapjs client events are handled here or in `createClient`.
var LDAP_PROXY_EVENTS = [
    'timeout',
    'socketTimeout'
];


//---- LdapAuth exported class

/**
 * Create an LDAP auth class. Primary usage is the `.authenticate` method.
 *
 * @param opts {Object} Config options. Keys (required, unless says
 *      otherwise) are:
 *    url {String} E.g. 'ldaps://ldap.example.com:663'
 *    adminDn {String} E.g. 'uid=myapp,ou=users,o=example.com'
 *    adminPassword {String} Password for adminDn.
 *    searchBase {String} The base DN from which to search for users by
 *        username. E.g. 'ou=users,o=example.com'
 *    searchFilter {String} LDAP search filter with which to find a user by
 *        username, e.g. '(uid={{username}})'. Use the literal '{{username}}'
 *        to have the given username be interpolated in for the LDAP
 *        search.
 *    log {Bunyan Logger} Optional. If given this will result in TRACE-level
 *        logging for component:ldapauth.
 *    verbose {Boolean} Optional, default false. If `log` is also given,
 *        this will add TRACE-level logging for ldapjs (quite verbose).
 *    cache {Boolean} Optional, default false. If true, then up to 100
 *        credentials at a time will be cached for 5 minutes.
 *    timeout {Integer} Optional, default Infinity. How long the client should
 *        let operations live for before timing out.
 *    connectTimeout {Integer} Optional, default is up to the OS. How long the
 *        client should wait before timing out on TCP connections.
 *    tlsOptions {Object} Additional options passed to the TLS connection layer
 *        when connecting via ldaps://. See
 *        http://nodejs.org/api/tls.html#tls_tls_connect_options_callback
 *        for available options
 *    retry {Object} Optional:
 *          - maxDelay {Number} maximum amount of time between retries
 *          - retries {Number} maximum # of retries
 */
function LdapAuth(opts) {
    assert.string(opts.url, 'opts.url');
    assert.ok(opts.adminDn, 'opts.adminDn');
    assert.ok(opts.searchBase, 'opts.searchBase');
    assert.ok(opts.searchFilter, 'opts.searchFilter');

    var self = this;
    EventEmitter.call(this);

    this.opts = opts;
    this.log = opts.log && opts.log.child({component: 'ldapauth'}, true);
    if (opts.cache) {
        var Cache = require('./cache');
        this.userCache = new Cache(100, 300, this.log, 'user');
    }
    this._salt = bcrypt.genSaltSync();

    this._adminOpts = {
        connectTimeout: opts.connectTimeout,
        credentials: {
            dn: opts.adminDn,
            passwd: opts.adminPassword
        },
        log: opts.verbose ? self.log : undefined,
        retry: opts.retry || {},
        tlsOptions: opts.tlsOptions,
        timeout: opts.timeout,
        url: opts.url
    };
    (function adminConnect() {
        self._adminConnecting = self._createClient(self._adminOpts, function (err, client) {
            self._adminConnecting = false;

            // We only get error if credentials are invalid
            if (err) {
                self.emit('error', err);
                return;
            }

            if (self.closed && client) {
                client.unbind();
                return;
            }

            function handleClose() {
                if (self._adminClient && !self._adminConnecting && !self.closed) {
                    self.log && self.log.warn(err, 'admin LDAP client disconnected');
                    self._adminClient = null;
                    adminConnect();
                }
            }

            client.once('error', handleClose);
            client.once('close', handleClose);
            LDAP_PROXY_EVENTS.forEach(function reEmit(event) {
                client.on(event, self.emit.bind(self, event));
            });

            self._adminClient = client;
            self.emit('connect');
        });
    })();
}
util.inherits(LdapAuth, EventEmitter);


// TODO: change all this to pull bind OUT of the retry section
LdapAuth.prototype._createClient = function _createClient(opts, cb) {
    assert.object(opts, 'options');
    assert.func(cb, 'callback');
    var self = this;

    cb = once(cb);

    var dn = opts.credentials.dn;
    var log = opts.log;
    var passwd = opts.credentials.passwd;
    var retryOpts = objCopy(opts.retry || {});
    retryOpts.maxDelay = retryOpts.maxDelay || retryOpts.maxTimeout || 30000;
    retryOpts.retries = retryOpts.retries || Infinity;

    function _createClientAttempt(_, _cb) {
        function onConnect() {
            client.removeListener('error', onError);
            log && log.trace('connected');
            if (self.closed) {
                client.socket.end();
                _cb();
                return;
            }
            client.bind(dn, passwd, function (err) {
                if (self.closed) {
                    client.socket.end();
                    _cb();
                    return;
                }
                if (err) {
                    if (err.name === 'InvalidCredentialsError') {
                        log && log.trace({bindDn: dn, err: err},
                            'invalid credentials; aborting retries');
                        cb(err);
                        client.socket.end();
                        retry.abort();
                    } else {
                        log && log.trace({bindDn: dn, err: err},
                            'unexpected bind error');
                        _cb(err);
                    }
                    return;
                }

                log && log.trace({bindDn: dn}, 'connected and bound');
                client.socket.setKeepAlive(true);
                _cb(null, client);
            });
        }

        function onError(err) {
            client.removeListener('connect', onConnect);
            _cb(err);
        }

        var client = ldap.createClient(opts);
        client.once('connect', onConnect);
        client.once('error', onError);
        client.once('connectTimeout', function () {
            onError(new Error('connect timeout'));
        });
    }

    var retry = backoff.call(_createClientAttempt, null, cb);
    retry.setStrategy(new backoff.ExponentialStrategy(retryOpts));
    retry.failAfter(retryOpts.retries);

    retry.on('backoff', function (number, delay) {
        var level;
        if (number === 0) {
            level = 'info';
        } else if (number < 5) {
            level = 'warn';
        } else {
            level = 'error';
        }
        log && log[level]({attempt: number, delay: delay},
            'connection attempt failed');
    });

    retry.start();
    return (retry);
}



LdapAuth.prototype.close = function close(cb) {
    assert.func(cb, 'callback');
    var self = this;
    cb = once(cb);

    this.closed = true;
    if (!this._adminClient) {
        if (this._adminConnecting) {
            this._adminConnecting.abort();
        }
        cb();
        return;
    }

    LDAP_PROXY_EVENTS.forEach(function reEmit(event) {
        self._adminClient.removeAllListeners(event);
    });

    this._adminClient.unbind(function (err) {
        if (err) {
            cb(err);
        } else {
            process.nextTick(self.emit.bind(self, 'close'));
            cb();
        }
    });
};


/**
 * Find the user record for the given username.
 *
 * @param username {String}
 * @param callback {Function} `function (err, user)`. If no such user is
 *    found but no error processing, then `user` is undefined.
 *
 */
LdapAuth.prototype._findUser = function (username, callback) {
    var self = this;
    if (!username) {
        return callback(new Error("empty username"));
    }

    if (!this._adminClient) {
        return callback(new Error("LDAP connection is not yet bound"));
    }

    var searchFilter = self.opts.searchFilter.replace('{{username}}', username);
    var opts = {
        filter: searchFilter,
        scope: 'sub'
    };
    self._adminClient.search(self.opts.searchBase, opts,
        function (err, result) {
            if (err) {
                self.log && self.log.trace(err, 'ldap authenticate: search error');
                return callback(err);
            }
            var items = [];
            result.on('searchEntry', function (entry) {
                items.push(entry.object);
            });
            result.on('error', function (err) {
                self.log && self.log.trace(err,
                    'ldap authenticate: search error event');
                return callback(err);
            });
            result.on('end', function (result) {
                if (result.status !== 0) {
                    var err = 'non-zero status from LDAP search: ' + result.status;
                    self.log && self.log.trace(err, 'ldap authenticate');
                    return callback(err);
                }
                switch (items.length) {
                case 0:
                    return callback();
                case 1:
                    return callback(null, items[0])
                default:
                    return callback(format(
                        'unexpected number of matches (%s) for "%s" username',
                        items.length, username));
                }
            });
        });
}


/**
 *
 */
LdapAuth.prototype.authenticate = function (username, password, callback) {
    var self = this;
    var opts = self.opts;
    var log = self.log;

    if (self.opts.cache) {
        // Check cache. 'cached' is `{password: <hashed-password>, user: <user>}`.
        var cached = self.userCache.get(username);
        if (cached && bcrypt.compareSync(password, cached.password)) {
            return callback(null, cached.user)
        }
    }

    // 1. Find the user DN in question.
    self._findUser(username, function (err, user) {
        if (err)
            return callback(err);
        if (!user)
            return callback(format('no such user: "%s"', username));

        // 2. Attempt to bind as that user to check password.
        var userOpts = {
            connectTimeout: opts.connectTimeout,
            credentials: {
                dn: user.dn,
                passwd: password
            },
            log: opts.verbose ? log : undefined,
            retry: opts.retry || {},
            tlsOptions: opts.tlsOptions,
            timeout: opts.timeout,
            url: opts.url
        };
        self._createClient(userOpts, function (err, client) {
            // We only get error if credentials are invalid.
            if (err) {
                log && log.trace('ldap authenticate: bind error: %s', err);
                return callback(err);
            }
            client.unbind(function (unbindErr) {
                log && log.trace(unbindErr, 'error unbinding user client (ignoring)');
                if (self.opts.cache) {
                    bcrypt.hash(password, self._salt, function (err, hash) {
                        self.userCache.set(username, {
                            password: hash,
                            user: user
                        });
                        return callback(null, user);
                    });
                } else {
                    return callback(null, user);
                }
            });
        });
    });
}



module.exports = LdapAuth;
