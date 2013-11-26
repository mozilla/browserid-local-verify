/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* global describe,it,require */

const
should = require('should'),
BrowserID = require('../'),
IdP = require('./lib/idp.js'),
Client = require('./lib/client.js'),
jwcrypto = require('jwcrypto');

require("jwcrypto/lib/algs/rs");
require("jwcrypto/lib/algs/ds");

describe('idp extra claims', function() {
  // a local idp with a 1s delay in serving support documents
  var idp = new IdP();
  var browserid = new BrowserID({ insecureSSL: true});
  var client;

  it('test idps should start up', function(done) {
    idp.start(done);
  });

  it('validation of basic assertion signed by IdP should succeed', function(done) {
    client = new Client({ idp: idp });

    // manually generate a cert with extra claims
    client.certificate({
      claims: {
        email: 'bob@example.com',
        uuid: '0ee70eb8-9b5b-49d7-8973-d587ed06b933'
      }
    }, function(err) {
      should.not.exist(err);
      client.assertion({ audience: 'http://example.com' }, function(err, assertion) {
        browserid.verify({
          assertion: assertion,
          audience: 'http://example.com'
        }, function(err, details) {
          should.not.exist(err);
          details.idpClaims.should.be.type('object');
          details.idpClaims.email.should.equal('bob@example.com');
          details.idpClaims.uuid.should.equal('0ee70eb8-9b5b-49d7-8973-d587ed06b933');
          done(err);
        });
      });
    });
  });

  it('test idp should shut down', function(done) {
    idp.stop(done);
  });
});
