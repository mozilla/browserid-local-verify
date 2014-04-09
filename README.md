[![Build Status](https://travis-ci.org/mozilla/browserid-local-verify.png?branch=master)](https://travis-ci.org/mozilla/browserid-local-verify)

# A node.js BrowserID verification library

This repository contains a node.js library for local verification of BrowserID assertions. It is used by [this standalone verifier](https://github.com/mozilla/browserid-verifier).

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

    browserid.lookup({
      domain: "mozilla.org"
    }, function(err, details) {
      // check err
      console.log(details.authority);
      console.log(details.pubKey);
      console.log(details.delegationChain);
    });

## configuration

All functions accept configuration parameters documented below.

    browserid.lookup({
      httpTimeout: 5.0,
      domain: "mozilla.org"
    }, function(err, details) {
      ...
    });

Or you can allocate a library instance.  This allows you to specify configuration once at instantiation time.  Any configuration parameters or function arguments may be specified a instantiation time and become the default for subsequently invoked functions:

    var BrowserID = require('browserid-local-verify');

    var b = new BrowserID({ httpTimeout: 20.0 });
    b.lookup({ domain: "mozilla.org" }, function(err, details) {
      // ...
    });

## Configuration and Arguments

### Common Arguments

* **httpRequest**: A function that allows the client to control how http requests are performed.
  * input arguments: (domain, path, callback)
  * callback argbuments: (err, statusCode, headers, body)
* **httpTimeout**: How long in seconds we should wait for a response when looking up a well-known document over HTTP. (default: 10)
* **maxDelegations**: How many times authority may be delegated.
* **insecureSSL**: When true, invalid SSL certificates are ignored (NEVER use this in production).
* **fallback**: A domain that is authoritative when support document lookup fails for the prinicpal email address's domain.

### lookup specific

* **domain**: the domain for which we should lookup the support document
* **principalDomain**: the domain of the email address for which we should discover the support document of the authority

### verification specific

* **now**: override the current time for purposes of assertion verification. (useful for testing)
* **assertion**: the assertion to verify
* **audience**: the expected assertion audience
* **trustedIssuers**: An array of domains that will be trusted to vouch for any identity, regardless of the authority as determined from the email addresses domain.

## debug output and metrics

The BrowserID class emits events:

    var b = new BrowserID();

    b.on('debug', function(msg) {
      console.log('debug output:', msg);
    });

    b.on('metric', function(metric, value) {
      console.log(metric + ":", value);
    });

    b.lookup("mozilla.org", function(err, details) {
      // ...
    });
