/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* global describe,it,require */

const
should = require('should'),
BrowserID = require('../'),
IdP = require('./lib/idp.js'),
Client = require('./lib/client.js'),
jwcrypto = require('jwcrypto');

require("jwcrypto/lib/algs/rs");
require("jwcrypto/lib/algs/ds");

// This test verifies that the library passes ?domain= properly when fetching
// support documents.  This is the protocol feature that supports an IdP serving
// different support documents based on the domain being requested.  The Persona
// "Identity Bridging" feature is built on this.
describe('domain GET param when fetching well-known', function() {
  // an "identity bridge"
  var bridge = new IdP();
  // a fallback provider that will delegate to the bridge when presented with
  // an email domain that
  var fallback = new IdP({
    dynamicWellKnown: function(url, cb) {
      if (url.indexOf('domain=bridged') !== -1) {
        cb(null, { authority: bridge.domain() });
      } else {
        cb(null, fallback.wellKnown());
      }
    }
  });
  var client;

  it('test idps should start up', function(done) {
    bridge.start(function(err) {
      fallback.start(function(err1) {
        done(err || err1);
      });
    });
  });

  it('assertion for fallback vouched email should succeed', function(done) {
    // user has an email from idp, but fallback will be used for certificate
    client = new Client({
      idp: fallback,
      email: "user@example.com"
    });

    client.assertion({ audience: 'http://example.com' }, function(err, assertion) {
      BrowserID.verify({
        insecureSSL: true,
        fallback: fallback.domain(),
        httpTimeout: 0.1, // fail faster for prompt tests
        assertion: assertion,
        audience: 'http://example.com'
      }, done);
    });
  });

  it('assertion for bridge vouched email should succeed', function(done) {
    // user has an email from idp, but fallback will be used for certificate
    client = new Client({
      idp: bridge,
      email: "user@bridged"
    });

    client.assertion({ audience: 'http://example.com' }, function(err, assertion) {
      BrowserID.verify({
        insecureSSL: true,
        fallback: fallback.domain(),
        httpTimeout: 0.1, // fail faster for prompt tests
        assertion: assertion,
        audience: 'http://example.com'
      }, done);
    });
  });

  it('test idp should shut down', function(done) {
    bridge.stop(function(err) {
      fallback.stop(function(err1) {
        done(err || err1);
      });
    });
  });
});
