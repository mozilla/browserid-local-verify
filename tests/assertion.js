/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* global describe,it,require */

const
should = require('should'),
BrowserID = require('../'),
IdP = require('./lib/idp.js'),
Client = require('./lib/client.js');

describe('assertion verification, basic', function() {
  // a local idp with a 1s delay in serving support documents
  var idp = new IdP();
  var browserid = new BrowserID({ insecureSSL: true});
  var client;

  it('test idps should start up', function(done) {
    idp.start(done);
  });

  it('validation of basic assertion signed by IdP should succeed', function(done) {
    client = new Client({ idp: idp });

    // allocate a new "client".  She has an email and idp as specified below
    // generate an assertion (and all pre-requisites)
    client.assertion({ audience: 'http://example.com' }, function(err, assertion) {
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
        done(err);
      });
    });
  });

  it('validation of basic assertion signed by Fallback should succeed', function(done) {
    client = new Client({
      idp: idp,
      email: 'test@nonprimary.example.com'
    });

    // allocate a new "client".  She has an email and idp as specified below
    // generate an assertion (and all pre-requisites)
    client.assertion({ audience: 'http://example.com' }, function(err, assertion) {
      browserid.verify({
        fallback: idp.domain(),
        httpTimeout: 0.1,
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
        done(err);
      });
    });
  });

  it('validation of chained assertions should fail', function(done) {
    client = new Client({ idp: idp });

    // allocate a new "client".  She has an email and idp as specified below
    // generate an assertion (and all pre-requisites)
    client.chainedAssertion({ audience: 'http://example.com' }, function(err, assertion) {
      browserid.verify({
        assertion: assertion,
        audience: 'http://example.com'
      }, function(err) {
        should.exists(err);
        err.should.equal('certificate chaining is not yet allowed');
        done();
      });
    });
  });

  it('validation of assertion with an invalid hostname in the email should fail', function(done) {
    client = new Client({
      idp: idp,
      email: 'test@example/com'
    });

    // allocate a new "client".  She has an email and idp as specified below
    // generate an assertion (and all pre-requisites)
    client.assertion({ audience: 'http://example.com' }, function(err, assertion) {
      browserid.verify({
        fallback: idp.domain(),
        httpTimeout: 0.1,
        assertion: assertion,
        audience: 'http://example.com'
      }, function(err) {
        should.exist(err);
        err.should.contain("untrusted assertion, doesn't contain an email, and issuer is untrusted");
        done();
      });
    });
  });

  it('validation of assertion with parens in the email hostname should fail', function(done) {
    client = new Client({
      idp: idp,
      email: 'test@(exam)ple.com'
    });

    // allocate a new "client".  She has an email and idp as specified below
    // generate an assertion (and all pre-requisites)
    client.assertion({ audience: 'http://example.com' }, function(err, assertion) {
      browserid.verify({
        fallback: idp.domain(),
        httpTimeout: 0.1,
        assertion: assertion,
        audience: 'http://example.com'
      }, function(err) {
        should.exist(err);
        err.should.contain("untrusted assertion, doesn't contain an email, and issuer is untrusted");
        done();
      });
    });
  });

  it('validation of assertion with aditional "@" symbols in the email should fail', function(done) {
    client = new Client({
      idp: idp,
      email: 'test@users.example.com@example.com'
    });

    // allocate a new "client".  She has an email and idp as specified below
    // generate an assertion (and all pre-requisites)
    client.assertion({ audience: 'http://example.com' }, function(err, assertion) {
      browserid.verify({
        fallback: idp.domain(),
        httpTimeout: 0.1,
        assertion: assertion,
        audience: 'http://example.com'
      }, function(err) {
        should.exist(err);
        err.should.contain("untrusted assertion, doesn't contain an email, and issuer is untrusted");
        done();
      });
    });
  });

  it('test idp should shut down', function(done) {
    idp.stop(done);
  });
});
