/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* global describe,it */

const
should = require('should'),
IdP = require('./lib/idp'),
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

    browserid.lookup({ insecureSSL: true, domain: idp.domain() }, function(err) {
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

    browserid.lookup({ insecureSSL: true, domain: idp.domain() }, function(err) {
      (err).should.contain("missing required property: 'provisioning'");

      // repair well-known
      idp.wellKnown(null);

      done();
    });
  });

  it('should reject invalid authorities', function(done) {
    var x = idp.wellKnown();
    x.authority = 'https://example.com';
    idp.wellKnown(x);

    browserid.lookup({ insecureSSL: true, domain: idp.domain() }, function(err) {
      (err).should.contain("the authority is not a valid hostname");

      // repair well-known
      idp.wellKnown(null);

      done();
    });
  });

  it('should reject invalid paths', function(done) {
    var x = idp.wellKnown();
    x.provisioning = 'foo';
    idp.wellKnown(x);

    browserid.lookup({ insecureSSL: true, domain: idp.domain() }, function(err) {
      (err).should.contain("paths must start with a slash");

      // repair well-known
      idp.wellKnown(null);

      done();
    });
  });

  it('should properly parse disabled: true', function(done) {
    idp.wellKnown({ disabled: true });

    browserid.lookup({ insecureSSL: true, domain: idp.domain() }, function(err, details) {
      should.not.exist(err);
      details.disabled.should.equal(true);

      // repair well-known
      idp.wellKnown(null);

      done();
    });
  });

  it('should properly parse disabled: false', function(done) {
    var x = idp.wellKnown();
    x.disabled = false;
    idp.wellKnown(x);

    browserid.lookup({ insecureSSL: true, domain: idp.domain() }, function(err, details) {
      should.not.exist(err);
      should.not.exist(details.disabled);

      // repair well-known
      idp.wellKnown(null);

      done();
    });
  });

  it('should properly parse disabled: 0', function(done) {
    var x = idp.wellKnown();
    x.disabled = 0;
    idp.wellKnown(x);

    browserid.lookup({ insecureSSL: true, domain: idp.domain() }, function(err) {
      (err).should.contain('disabled must be either true or false');

      // repair well-known
      idp.wellKnown(null);

      done();
    });
  });

  it('should properly parse disabled: "true"', function(done) {
    var x = idp.wellKnown();
    x.disabled = "true";
    idp.wellKnown(x);

    browserid.lookup({ insecureSSL: true, domain: idp.domain() }, function(err) {
      (err).should.contain('disabled must be either true or false');

      // repair well-known
      idp.wellKnown(null);

      done();
    });
  });

  it('shutdown of IdP should succeed', function(done) {
    idp.stop(done);
  });
});
