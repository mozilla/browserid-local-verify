/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* global describe,it,require */

const
should = require('should'),
BrowserID = require('../'),
IdP = require('./lib/idp.js').IdP,
Client = require('./lib/client.js'),
jwcrypto = require('jwcrypto');

require("jwcrypto/lib/algs/rs");
require("jwcrypto/lib/algs/ds");

describe('domain authority', function() {
  var idp = new IdP();
  var fallback = new IdP();
  var client;

  it('test idps should start up', function(done) {
    idp.start(function(err) {
      fallback.start(function(err1) {
        done(err || err1);
      });
    });
  });

  it('assertion by fallback when primary support is present should fail', function(done) {
    // user has an email from idp, but fallback will be used for certificate
    client = new Client({
      idp: fallback,
      email: "user@" + idp.domain()
    });

    client.assertion({ audience: 'http://example.com' }, function(err, assertion) {
      BrowserID.verify({
        insecureSSL: true,
        fallback: fallback.domain()
      }, assertion, 'http://example.com', function(err) {
          should.exist(err);
          (err).should.startWith("untrusted issuer");
          done(null);
        });
    });
  });

  it('test idp should shut down', function(done) {
    idp.stop(function(err) {
      fallback.stop(function(err1) {
        done(err || err1);
      });
    });
  });
});
