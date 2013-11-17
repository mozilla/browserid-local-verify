/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* global describe,it */

const
should = require('should'),
IdP = require('./lib/idp.js').IdP,
browserid = require('..');

describe('test idp implementation', function() {
  // and a new test IdP
  var idp = new IdP({});

  it('should allocate a new testing idp', function(done) {
    should.exist(idp);
    idp.start(function(err, details) {
      should.not.exist(err);
      (details).should.be.type('object');
      details.url.should.be.type('string');
      details.publicKey.should.be.type('object');
      details.url.should.equal(idp.url());
      (details.publicKey.serialize()).should.equal(idp.publicKey().serialize());
      done();
    });
  });

  it('should handle custom support documents', function(done) {
    idp.wellKnown({ custom: true});

    browserid.lookup({ insecureSSL: true }, idp.domain(), function(err) {
      (err).should.contain('support document missing');
      done();
    });
  });

  it('should shutdown gracefully', function(done) {
    idp.stop(function(err) {
      should.not.exist(err);
      done();
    });
  });
});
