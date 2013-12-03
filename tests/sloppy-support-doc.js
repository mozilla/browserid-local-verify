/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* global describe,it,require */

const
should = require('should'),
BrowserID = require('../'),
IdP = require('./lib/idp.js'),
Client = require('./lib/client.js');

describe('conditionally support sloppy well-known documents', function() {
  // a sloppy fallback that has no auth nor prov urls
  var fallback = new IdP();

  it('fallback idp should start up', function(done) {
    fallback.start(function(err) {
      should.not.exist(err);
      fallback.wellKnown({
        "public-key": fallback.publicKey().toSimpleObject()
      });
      done(err);
    });
  });

  it('assertion for fallback vouched email should succeed', function(done) {
    var client = new Client({
      idp: fallback,
      email: 'test@example.com'
    });

    client.assertion({ audience: 'http://example.com' }, function(err, assertion) {
      var browserid = new BrowserID({
        insecureSSL: true,
        httpTimeout: 0.1 // fail faster for prompt tests
      });

      browserid.verify({
        assertion: assertion,
        audience: 'http://example.com',
        fallback: fallback.domain()
      }, function(err, r) {
        should.not.exist(err);
        (r.email).should.equal('test@example.com');
        (r.audience).should.equal('http://example.com');
        done(err);
      });
    });
  });

  it('test idp should shut down', function(done) {
    fallback.stop(done);
  });
});
