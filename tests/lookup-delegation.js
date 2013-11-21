/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* global describe,it */

const
should = require('should'),
delegation = require('./lib/delegation.js'),
browserid = require('..');

describe('.well-known lookup, delegation', function() {
  var chain;

  it('allocation of delegation chain should succeed', function(done) {
    delegation(10, function(err, c) {
      chain = c;
      done(err);
    });
  });

  it('delegation chain should be followed', function(done) {
    browserid.lookup({
      insecureSSL: true,
      maxDelegations: 9
    }, chain[0].domain(), null, function(err, details) {
      should.not.exist(err);
      details.delegationChain.should.be.instanceof(Array).and.have.lengthOf(10);
      details.authoritativeDomain.should.equal(chain[9].domain());
      done(err);
    });
  });

  it('refuse to follow the delegation chain if too long', function(done) {
    browserid.lookup({
      insecureSSL: true,
      maxDelegations: 8
    }, null, chain[0].domain(), function(err) {
      should.exist(err);
      err.should.startWith('Too many hops while delegating authority');
      done(null);
    });
  });

  it('detect delegation cycles efficiently', function(done) {
    // create a cycle
    chain[8].delegation(chain[3].domain());

    browserid.lookup({
      insecureSSL: true,
      maxDelegations: 100
    }, chain[0].domain(), null, function(err) {
      should.exist(err);
      err.should.startWith('Circular reference in delegating authority');

      // repair the chain
      chain[8].delegation(chain[9].domain());

      done(null);
    });
  });

  it('should handle broken chains elegantly (slow idp)', function(done) {
    // now let's make the 7th link in the chain unresponsive (1s delay in response)
    chain[7].delay(1.0);

    browserid.lookup({
      insecureSSL: true,
      maxDelegations: 10,
      httpTimeout: 0.3 // only tolerate a 300ms delay
    }, chain[0].domain(), null, function(err) {
      should.exist(err);
      err.should.startWith('timeout trying to load');

      // remove the delay
      chain[7].delay(0);

      done(null);
    });
  });

  it('should handle broken chains elegantly (malformed .well-known)', function(done) {
    // now let's park a bogus well-known document
    chain[7].delegation(null);
    chain[7].wellKnown({ bogus: true });

    browserid.lookup({
      insecureSSL: true,
      maxDelegations: 10
    }, chain[0].domain(), null, function(err) {
      should.exist(err);
      err.should.startWith('bad support document');
      done(null);

      // fix the document
      chain[7].wellKnown(null);
      chain[7].delegation(chain[8].domain());
    });
  });

  it('shutdown of delegation chain should succeed', function(done) {
    chain.stop(done);
  });
});
