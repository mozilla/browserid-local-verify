/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* global describe,it,require */

const
should = require('should'),
browserid = require('../'),
IdP = require('./lib/idp.js').IdP,
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
    // XXX: let's make a library for this (under test/lib) so we can test the shit out of
    // assertion verification with terse and readable tests.

    // generate a keypair
    jwcrypto.generateKeypair({
      algorithm: 'DS',
      keysize: 128
    }, function(err, kp) {
      should.not.exist(err);

      // sign the public key with the idp's private, creating what we call around here
      // a 'cert'.
      jwcrypto.cert.sign({
        publicKey: kp.publicKey,
        principal: { email: 'test@' + idp.domain() }
      }, {
        issuer: idp.domain(),
        issuedAt: new Date(),
        expiresAt: (new Date() + (60 * 60)) // cert valid for 60 minutes
      }, null, idp.privateKey(), function(err, cert) {
        should.not.exist(err);

        // now that we have a signed cert, let's generate an assertion
        jwcrypto.assertion.sign(
          {}, { audience: 'http://example.com', expiresAt: (new Date() + 120) },
          kp.secretKey,
          function(err, signedContents) {
            should.not.exist(err);
            var assertion = jwcrypto.cert.bundle([cert], signedContents);

            // and finally, this assertion should verify
            browserid.verify(
              { insecureSSL: true },
              assertion, 'http://example.com',
              function(err, details) {
                console.log(details);
                done(err);
              });
          });
      });
    });
  });

  it('test idp should shut down', function(done) {
    idp.stop(done);
  });
});
