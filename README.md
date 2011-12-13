A simple node.js lib to authenticate against an LDAP server.

# Usage

    var LdapAuth = require('ldapauth');
    var options = {
        url: 'ldaps://ldap.example.com:663',
        adminDn: '...'
        
        ...
    {
    };
    var auth = new LdapAuth(options);
    ...
    auth.authenticate(username, password, function(err, user) { ... });
    ...
    auth.close(function(err) { ... })

# Install

    npm install ldapauth

# `LdapAuth` Config Options

[Use the source Luke](XXX)
