/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// jshinting (syntax checking) of the source

const
should = require('should'),
Verifier = require('../').Verifier,
IdP = require('./lib/idp.js').IdP;

describe('.well-known discovery', function() {
  var verifier = new Verifier({});
  var idp = new IdP({});

  it('test idp should start up', function(done) {
    idp.start(done);
  });

  // now let's test!
  // XXX

  it('test idp should shut down', function(done) {
    idp.stop(done);
  });
});
