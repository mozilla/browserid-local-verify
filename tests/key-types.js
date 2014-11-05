/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* global describe,it,require */

/* test that all permutations of key type and length for user key and
 * IdP key are supported by the verification library */

const
should = require('should'),
BrowserID = require('../'),
IdP = require('./lib/idp.js'),
Client = require('./lib/client.js'),
async = require('async');

describe('key size and type', function() {
  const keyTypes = [
    { algorithm: 'RS', keysize: 64 },
    { algorithm: 'RS', keysize: 128 },
    { algorithm: 'RS', keysize: 256 },
    { algorithm: 'DS', keysize: 128 },
    { algorithm: 'DS', keysize: 256 }
  ];

  // a local idp with a 1s delay in serving support documents
  var browserid = new BrowserID({ insecureSSL: true});

  it('all permutations (user / IdP) should pass basic assertion verification', function(done) {
    // on travis sometimes the default timeout (2s) just isn't enough
    this.timeout(10000);

    // for each key size and type...
    async.each(keyTypes, function(idpkt, done) {
      // we'll allocate an IdP with a domain key of that size/type...
      var idp = new IdP(idpkt);
      idp.start(function(err) {
        should.not.exist(err);
        // and for each key size and type...
        async.each(keyTypes, function(clientkt, done) {
          // we'll generate a user key...
          var client = new Client({
            idp: idp,
            keysize: clientkt.keysize,
            algorithm: clientkt.algorithm
          });
          // and using that user key we'll generate and assertion...
          client.assertion({ audience: 'http://example.com' }, function(err, assertion) {
            should.not.exist(err);
            // and that assertion should verify properly...
            browserid.verify({
              assertion: assertion,
              audience: 'http://example.com'
            }, function(err, details) {
              should.not.exist(err);
              (details).should.be.type('object');
              (details.audience).should.equal('http://example.com');
              // a basic sanity on expiration date
              var now = new Date();
              (details.expires).should.be.above(now - 60).and.should.be.above(now + 120);
              (details.issuer).should.equal(idp.domain());
              (details.email).should.equal(client.email());
              done(null);
            });
          });
        }, function(err) {
          should.not.exist(err);
          idp.stop(done);
        });
      });
    }, done);
  });
});
