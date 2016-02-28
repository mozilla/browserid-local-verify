/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* global describe,it */

const
should = require('should'),
validation = require('../lib/validation');

describe('url validation', function() {

  it('should reject badly-formed urls', function(done) {
    var INVALID_URLS = [
      "!@#%!$^!^$",
      "://host.com",
      "bogus://apps.mozillalabs.com",
      "http:",
      "http://host.com:76543",
      "http://host.com:0",
    ];
    INVALID_URLS.forEach(function(invalidUrl) {
      should.throws(function() {
        validation.validateUrl(invalidUrl);
      });
    });
    done();
  });

});
