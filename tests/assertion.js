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

// I hate this.
require("jwcrypto/lib/algs/rs");
require("jwcrypto/lib/algs/ds");

describe('assertion verification, basic', function() {
  // a local idp with a 1s delay in serving support documents
  var idp = new IdP();
  var browserid = new BrowserID({ insecureSSL: true});
  var client;

  it('test idps should start up', function(done) {
    idp.start(done);
  });

  it('validation of basic assertion signed by IdP should succeed', function(done) {
    client = new Client({ idp: idp });

    // allocate a new "client".  She has an email and idp as specified below
    // generate an assertion (and all pre-requisites)
    client.assertion({ audience: 'http://example.com' }, function(err, assertion) {
      browserid.verify(
        assertion, 'http://example.com',
        function(err, details) {
          // XXX: check details for pertinent values
          console.log(details);
          done(err);
        });
    });
  });

  it('validation of basic assertion signed by Fallback should succeed', function(done) {
    client = new Client({
      idp: idp,
      email: 'test@example,com'
    });

    // allocate a new "client".  She has an email and idp as specified below
    // generate an assertion (and all pre-requisites)
    client.assertion({ audience: 'http://example.com' }, function(err, assertion) {
      // XXX: now we must specify a fallback
      BrowserID.verify({
        insecureSSL: true,
        fallback: idp.domain()
      }, assertion, 'http://example.com', function(err) {
        // XXX: check details for pertinent values
        done(err);
      });
    });
  });

  it('test idp should shut down', function(done) {
    idp.stop(done);
  });
});
