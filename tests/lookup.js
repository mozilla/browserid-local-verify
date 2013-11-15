/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* global describe,it */

const
should = require('should'),
BrowserID = require('../'),
IdP = require('./lib/idp.js').IdP;

describe('.well-known lookup', function() {
  var idp = new IdP();

  var browserid = new BrowserID({
    httpRequest: function(domain, path, cb) {
      cb(null, 200, { 'Content-Type': 'application/json' } , '{ "disabled": true }');
    }
  });

  it('test idp should start up', function(done) {
    idp.start(done);
  });

  it('should work an over-ridden HTTP implementation', function(done) {
    browserid.lookup('example.com', function(err, details) {
      should.not.exist(err);
      details.disabled.should.equal(true);
      details.delegationChain.should.be.instanceof(Array).and.have.lengthOf(1);
      details.delegationChain[0].should.equal('example.com');
      details.authoritativeDomain.should.equal('example.com');
      done(err);
    });
  });

  it('test idp should shut down', function(done) {
    idp.stop(done);
  });
});
