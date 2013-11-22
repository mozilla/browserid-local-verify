/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* global describe,it,require */

const
should = require('should'),
BrowserID = require('../'),
IdP = require('./lib/idp.js').IdP,
Client = require('./lib/client.js'),
jwcrypto = require('jwcrypto');

require("jwcrypto/lib/algs/rs");
require("jwcrypto/lib/algs/ds");

describe('conditionally support sloppy well-known documents', function() {
  // a sloppy fallback that has no auth nor prov urls
  var fallback = new IdP({
    wellKnown: {
      "public-key": {
        "algorithm": "RS",
        "n":"13847129683346859941264989674568093903817733347507886483659072610887035115410884319746624743249873208613096773517649937232300491784030920639144918224162068671400821902037583483041672764299306953103026060664680502797174343514269310587598551716299517313631315828939375461655862731946934365379077922079015460490916404855526919865126417791640455294879012843461329126172228137733279330910651237329531496694237928709223634994176813985784350468828176558279934807392490900567770727183145892059849913866957956369313527767655739421507886573261431996201380835691492402207640696740537706612595819413637640492969110348638013564489",
        "e":"65537"
      }
    }
  });

  it('test idps should start up', function(done) {
    fallback.start(done);
  });

  it('assertion for fallback vouched email should succeed', function(done) {
    BrowserID.lookup({
      insecureSSL: true,
      httpTimeout: 0.1, // fail faster for prompt tests
      domain: fallback.domain(),
      allowURLOmission: true
    }, function(err) {
      done(err);
    });
  });

  it('test idp should shut down', function(done) {
    fallback.stop(done);
  });
});
