/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* global describe,it,require */

/* a test of assertion expiration time verification, as well as 'fuzzing'
 * features of client library to allow for minor time drift between the
 * server playing the IdP role, and he who verifies. */

const
should = require('should'),
BrowserID = require('../'),
IdP = require('./lib/idp.js').IdP,
Client = require('./lib/client.js');

function secsFromNow(adj) {
  var ms = new Date().valueOf();
  return (Math.floor(ms / 1000) + adj);
}

describe('assertion time verification', function() {
  var idp = new IdP();
  var browserid;

  it('test idp should start up', function(done) {
    idp.start(function(err) {
      should.not.exist(err);
      browserid = new BrowserID({
        insecureSSL: true,
        fallback: idp.domain()
      });
      done(null);
    });
  });

  it('assertions backed by expired certificates should fail to verify', function(done) {
    var client = new Client({
      idp: idp,
      email: 'test@example,com',
      certificateIssueTime: secsFromNow(-(24*60*60)) // one day ago
    });

    // allocate a new "client".  She has an email and idp as specified below
    // generate an assertion (and all pre-requisites)
    client.assertion({ audience: 'http://example.com' }, function(err, assertion) {
      should.not.exist(err);
      browserid.verify(assertion, 'http://example.com', function(err) {
        should.exist(err);
        (err).should.contain("certificate expired");
        done(null);
      });
    });
  });

  it('assertions backed by certificates from the future should fail to verify', function(done) {
    var client = new Client({
      idp: idp,
      email: 'test@example,com',
      certificateIssueTime: secsFromNow((24*60*60)) // a day from now
    });

    // allocate a new "client".  She has an email and idp as specified below
    // generate an assertion (and all pre-requisites)
    client.assertion({ audience: 'http://example.com' }, function(err, assertion) {
      should.not.exist(err);
      browserid.verify(assertion, 'http://example.com', function(err) {
        should.exist(err);
        (err).should.contain("certificate issued later");
        done(null);
      });
    });
  });

  it('expired assertions should fail to verify', function(done) {
    var client = new Client({
      idp: idp,
      email: 'test@example,com'
    });

    // allocate a new "client".  She has an email and idp as specified below
    // generate an assertion (and all pre-requisites)
    client.assertion({
      audience: 'http://example.com',
      issueTime: secsFromNow(-(3*60)) // 3 minutes ago
    }, function(err, assertion) {
      should.not.exist(err);
      browserid.verify(assertion, 'http://example.com', function(err) {
        should.exist(err);
        (err).should.contain("assertion expired");
        done(null);
      });
    });
  });

  it('assertions from the future should fail to verify', function(done) {
    var client = new Client({
      idp: idp,
      email: 'test@example,com'
    });

    // allocate a new "client".  She has an email and idp as specified below
    // generate an assertion (and all pre-requisites)
    client.assertion({
      audience: 'http://example.com',
      issueTime: secsFromNow(3*60) // three minutes from now
    }, function(err, assertion) {
      should.not.exist(err);
      browserid.verify(assertion, 'http://example.com', function(err) {
        should.exist(err);
        (err).should.contain("assertion issued later than verification date");
        done(null);
      });
    });
  });

  it('test idp should shut down', function(done) {
    idp.stop(done);
  });
});
