/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* global describe,it,require */

const
url = require('url'),
should = require('should'),
BrowserID = require('../'),
IdP = require('./lib/idp.js'),
Proxy = require('./lib/proxy.js'),
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

  var badContentType = new BrowserID({
    httpRequest: function(domain, path, cb) {
      cb(null, 200, { 'Content-Type': 'text/plain' } , '{ "disabled": true }');
    }
  });

  // A local proxy server.
  var proxy = new Proxy();

  it('test servers should start up', function(done) {
    async.parallel([
      function(cb) {
        slowidp.start(cb);
      },
      function(cb) {
        disabledidp.start(cb);
      },
      function(cb) {
        redirectidp.start(cb);
      },
      function(cb) {
        proxy.start(cb);
      }
    ], done);
  });

  it('should work with the built-in HTTP implementation', function(done) {
    browserid.lookup({ domain: disabledidp.domain() }, function(err, details) {
      should.not.exist(err);
      details.disabled.should.equal(true);
      details.delegationChain.should.be.instanceof(Array).and.have.lengthOf(1);
      details.delegationChain[0].should.equal(disabledidp.domain());
      details.authoritativeDomain.should.equal(disabledidp.domain());
      done(err);
    });
  });

  it('should work an over-ridden HTTP implementation', function(done) {
    overRiddenBrowserid.lookup({ domain: 'example.com' }, function(err, details) {
      should.not.exist(err);
      details.disabled.should.equal(true);
      details.delegationChain.should.be.instanceof(Array).and.have.lengthOf(1);
      details.delegationChain[0].should.equal('example.com');
      details.authoritativeDomain.should.equal('example.com');
      done(err);
    });
  });

  it('should timeout for slow http responses', function(done) {
    browserid.lookup({ domain: slowidp.domain() }, function(err) {
      should.exist(err);
      err.should.startWith('timeout trying to load well-known for 127.0.0.1:');
      done(null);
    });
  });

  it('should refuse to follow http redirects', function(done) {
    browserid.lookup({ domain: redirectidp.domain() }, function(err) {
      should.exist(err);
      err.should.endWith('is not a browserid primary - redirection not supported for support documents');
      done(null);
    });
  });

  it('should fail on wrong content type', function(done) {
    badContentType.lookup({ domain: redirectidp.domain() }, function(err) {
      should.exist(err);
      (err).should.contain('non "application/json" response');
      done(null);
    });
  });

  it('should use proxy server when $http_proxy is set', function(done) {
    var origHttpsProxy = process.env.https_proxy || '';
    process.env.https_proxy = proxy.url();
    proxy.clearNumRequests();
    browserid.lookup({ domain: disabledidp.domain() }, function(err, details) {
      should.not.exist(err);
      details.disabled.should.equal(true);
      should(proxy.numRequests()).equal(1);
      process.env.https_proxy = origHttpsProxy;
      done(err);
    });
  });

  it('should bypass proxy server when $no_proxy is set to *', function(done) {
    var origHttpsProxy = process.env.https_proxy || '';
    var origNoProxy = process.env.no_proxy || '';
    process.env.https_proxy = proxy.url();
    process.env.no_proxy = '*';
    proxy.clearNumRequests();
    browserid.lookup({ domain: disabledidp.domain() }, function(err, details) {
      should.not.exist(err);
      details.disabled.should.equal(true);
      should(proxy.numRequests()).equal(0);
      process.env.no_proxy = origNoProxy;
      process.env.https_proxy = origHttpsProxy;
      done(err);
    });
  });

  it('should bypass proxy server when host is in $no_proxy', function(done) {
    var origHttpsProxy = process.env.https_proxy || '';
    var origNoProxy = process.env.no_proxy || '';
    var idpHostname = url.parse(disabledidp.url()).hostname;
    process.env.https_proxy = proxy.url();
    process.env.no_proxy = 'example.com, ' + idpHostname;
    proxy.clearNumRequests();
    browserid.lookup({ domain: disabledidp.domain() }, function(err, details) {
      should.not.exist(err);
      details.disabled.should.equal(true);
      should(proxy.numRequests()).equal(0);
      process.env.no_proxy = origNoProxy;
      process.env.https_proxy = origHttpsProxy;
      done(err);
    });
  });

  it('should use proxy server when host is not in $no_proxy', function(done) {
    var origHttpsProxy = process.env.https_proxy || '';
    var origNoProxy = process.env.no_proxy || '';
    process.env.https_proxy = proxy.url();
    process.env.no_proxy = 'example1.com, example1.com';
    proxy.clearNumRequests();
    browserid.lookup({ domain: disabledidp.domain() }, function(err, details) {
      should.not.exist(err);
      details.disabled.should.equal(true);
      should(proxy.numRequests()).equal(1);
      process.env.no_proxy = origNoProxy;
      process.env.https_proxy = origHttpsProxy;
      done(err);
    });
  });

  it('test servers should shut down', function(done) {
    async.parallel([
      function(cb) {
        slowidp.stop(cb);
      },
      function(cb) {
        disabledidp.stop(cb);
      },
      function(cb) {
        redirectidp.stop(cb);
      },
      function(cb) {
        proxy.stop(cb);
      }
    ], done);
  });
});
