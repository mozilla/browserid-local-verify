/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* global describe,it,require */

const
should = require('should'),
browserid = require('../'),
IdP = require('./lib/idp.js').IdP,
Client = require('./lib/client.js'),
jwcrypto = require('jwcrypto');

// I hate this.
require("jwcrypto/lib/algs/rs");
require("jwcrypto/lib/algs/ds");

describe('assertion verification, basic', function() {
  // a local idp with a 1s delay in serving support documents
  var idp = new IdP();

  it('test idps should start up', function(done) {
    idp.start(done);
  });

  it('validation of basic assertion should succeed', function(done) {
    // allocate a new "client".  She has an email and idp as specified below
    var client = new Client({
      email: 'test@' + idp.domain(),
      idp: idp
    });

    // generate an assertion (and all pre-requisites)
    client.assertion({ audience: 'http://example.com' }, function(err, assertion) {
      browserid.verify(
        { insecureSSL: true },
        assertion, 'http://example.com',
        function(err, details) {
          console.log(details);
          done(err);
        });
    });
  });

  it('test idp should shut down', function(done) {
    idp.stop(done);
  });
});
