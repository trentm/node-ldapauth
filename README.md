A simple node.js lib to authenticate against an LDAP server.


# Usage

    var LdapAuth = require('ldapauth');
    var options = {
        url: 'ldaps://ldap.example.com:663',
        ...
    };
    var auth = new LdapAuth(options);
    ...
    auth.authenticate(username, password, function(err, user) { ... });
    ...
    auth.close(function(err) { ... })


# Install

    npm install ldapauth


# License

MIT. See "LICENSE" file.


# `LdapAuth` Config Options

[Use the source Luke](https://github.com/trentm/node-ldapauth/blob/master/lib/ldapauth.js#L25-45)
