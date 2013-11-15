/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// jshinting (syntax checking) of the source

const
should = require('should'),
Verifier = require('../').Verifier,
Secondary = require('./lib/secondary.js').Secondary;

describe('.well-known discovery', function() {
  // for this test we'll need a verifier instance
  var verifier = new Verifier({});

  // and a new sample secondary
  var secondary = new Secondary({});

  // note, this is very low level testing of the verification library,
  // perhaps we can break it into a different test file
  it('should start with allocation of a new verifier', function(done) {
    should.exist(verifier);
    (verifier).should.be.type('object');
    done();
  });

  // note, this is testing some of the testing infrastructure, perhaps
  // can be in a distinct 'test-secondary.js' file.
  it('should start with allocation of a new secondary', function(done) {
    should.exist(secondary);
    secondary.start(function(err, details) {
      should.not.exist(err);
      // XXX: verify details available through secondary and
      // through function calls on secondary
      (details).should.be.type('object');
      done();
    });
  })
});
