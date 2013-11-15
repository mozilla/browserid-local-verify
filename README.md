[![Build Status](https://travis-ci.org/lloyd/browserid-local-verify.png?branch=master)](https://travis-ci.org/lloyd/browserid-local-verify)

(status:  **experimental**, **incomplete**)

# A node.js BrowserID verification library

This repository contains a node.js library for local verification of BrowserID assertions.

The library has the following scope and features:

  * **authoritative domain lookup** - given a domain, follow the browserid standard to resolve it (following authority delagation) into the ultimatly responsible domain and its public key.
  * **.well-known document parsing**
  * **(multiple) secondary IdP support** - The library can be initialized with a set of trusted "fallback IdPs" that are considered authoritative when lookup fails (no support document can be found).
  * **external HTTP implementation** - You can use node.js's http implementation, or override it and support your own (useful for HTTP proxied environments)
  * **command line tools** - all of these features are exposed via command line tools for manual inspection of domain's persona configuration.
  * **assertion verification** - the features above all fuel a simple yet flexible API for local verification of assertions.

# Alternatives

This library is targeted at robust local verification, to subsume all of the features required by mozilla's implementation of assertion verification in [Persona][].  If you're looking for a clean and simple library appropriate for website use (using the verifier hosted by persona), see [browserid-verify][].

[Persona]: https://persona.org
[browserid-verify]: https://npmjs.org/browserid-verify

# USAGE

    npm install persona-verifier-lib

## (simple) verifying an assertion

    var browserid = require('browserid-local-verify');

    browserid.verify({
      assertion: assertion,
      audience:  "http://example.com"
    }, function(err, details) {
      console.log(details);
    });

## looking up an authority for a domain

    var browserid = require('browserid-local-verify');

    browserid.lookup("mozilla.org", function(err, details) {
      // check err
      console.log(details.authority);
      console.log(details.pubKey);
      console.log(details.delegationChain);
    });

XXX: more to come, this is just a strawthing so far.

## configuration

To configure the library you can either pass an object as the first parameter to a supported function:

    browserid.lookup({ httpProxy: 'http://example.com:8080' }, "mozilla.org", function(err, details) {
      ...
    });

Or you can allocate a library instance.  This allows you to specify configuration once at instantiation time:

    var BrowserID = require('browserid-local-verify');
    
    var b = new BrowserID({ httpTimeout: 20.0 });
    b.lookup("mozilla.org", function(err, details) {
      // ...
    });

## knobs and switches:

* **httpRequest**: A function that allows the client to control how http requests are performed.
  * input arguments: (domain, path, callback)
  * callback argbuments: (err, statusCode, headers, body)
* **httpTimeout**: How long in seconds we should wait for a response when looking up a well-known document over HTTP. (default: 10)
* **maxDelegations**: How many times authority may be delegated.
* **insecureSSL**: When true, invalid SSL certificates are ignored (NEVER use this in production).

## debug output

The BrowserID class emits events:

    var b = new BrowserID({ httpTimeout: 20.0 });
    
    b.on('info', function() {
      console.log('got some 411', arguments);
    });
    
    b.lookup("mozilla.org", function(err, details) {
      // ...
    });
