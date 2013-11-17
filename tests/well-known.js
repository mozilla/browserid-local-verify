/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* global describe,it */

const
should = require('should'),
IdP = require('./lib/idp').IdP,
browserid = require('..');

describe('.well-known lookup, malformed', function() {
  var idp = new IdP();

  it('startup of IdP should succeed', function(done) {
    idp.start(done);
  });

  it('should handle bogus public key', function(done) {
    var x = idp.wellKnown();
    x['public-key'].n += "bogus";
    idp.wellKnown(x);

    browserid.lookup({ insecureSSL: true }, idp.domain(), function(err) {
      (err).should.contain('mal-formed public key');

      // repair well-known
      idp.wellKnown(null);

      done();
    });
  });

  it('should handle missing required fields', function(done) {
    var x = idp.wellKnown();
    delete x.provisioning;
    idp.wellKnown(x);

    browserid.lookup({ insecureSSL: true }, idp.domain(), function(err) {
      (err).should.contain("missing required 'provisioning'");

      // repair well-known
      idp.wellKnown(null);

      done();
    });
  });

  it('should properly parse disabled: true', function(done) {
    idp.wellKnown({ disabled: true });

    browserid.lookup({ insecureSSL: true }, idp.domain(), function(err, details) {
      should.not.exist(err);
      details.disabled.should.equal(true);

      // repair well-known
      idp.wellKnown(null);

      done();
    });
  });

  it('shutdown of IdP should succeed', function(done) {
    idp.stop(done);
  });
});
