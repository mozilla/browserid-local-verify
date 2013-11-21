/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* global describe,it,require */

const
should = require('should'),
BrowserID = require('../'),
IdP = require('./lib/idp.js').IdP,
async = require('async');

describe('.well-known lookup transport tests (HTTP)', function() {
  // a local idp with a 1s delay in serving support documents
  var slowidp = new IdP({
    delay: 1.0
  });

  // a local idp that serves disabled support documents
  var disabledidp = new IdP({
    disabled: true,
  });

  // an idp that HTTP redirects
  var redirectidp = new IdP({
    http_redirect: 'example.com'
  });


  // a client library instance which ignores invalid SSL certs, and
  // only tolerates a 100ms delay in HTTP requests
  var browserid = new BrowserID({
    insecureSSL: true,
    httpTimeout: 0.1
  });

  // A client library instance that over-rides the built in HTTP
  // implementation
  var overRiddenBrowserid = new BrowserID({
    httpRequest: function(domain, path, cb) {
      cb(null, 200, { 'Content-Type': 'application/json' } , '{ "disabled": true }');
    }
  });

  it('test idps should start up', function(done) {
    async.parallel([
      function(cb) {
        slowidp.start(cb);
      },
      function(cb) {
        disabledidp.start(cb);
      },
      function(cb) {
        redirectidp.start(cb);
      }
    ], done);
  });

  it('should work with the built-in HTTP implementation', function(done) {
    browserid.lookup(disabledidp.domain(), null, function(err, details) {
      should.not.exist(err);
      details.disabled.should.equal(true);
      details.delegationChain.should.be.instanceof(Array).and.have.lengthOf(1);
      details.delegationChain[0].should.equal(disabledidp.domain());
      details.authoritativeDomain.should.equal(disabledidp.domain());
      done(err);
    });
  });


  it('should work an over-ridden HTTP implementation', function(done) {
    overRiddenBrowserid.lookup('example.com', null, function(err, details) {
      should.not.exist(err);
      details.disabled.should.equal(true);
      details.delegationChain.should.be.instanceof(Array).and.have.lengthOf(1);
      details.delegationChain[0].should.equal('example.com');
      details.authoritativeDomain.should.equal('example.com');
      done(err);
    });
  });

  it('should timeout for slow http responses', function(done) {
    browserid.lookup(slowidp.domain(), null, function(err) {
      should.exist(err);
      err.should.startWith('timeout trying to load well-known for 127.0.0.1:');
      done(null);
    });
  });

  it('should refuse to follow http redirects', function(done) {
    browserid.lookup(redirectidp.domain(), null, function(err) {
      should.exist(err);
      err.should.endWith('is not a browserid primary - redirection not supported for support documents');
      done(null);
    });
  });

  it('test idp should shut down', function(done) {
    async.parallel([
      function(cb) {
        slowidp.stop(cb);
      },
      function(cb) {
        disabledidp.stop(cb);
      },
      function(cb) {
        redirectidp.stop(cb);
      }
    ], done);
  });
});
