/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* global describe,it,require */

// test of audience matching

const
compareAudiences = require('..').compareAudiences,
should = require('should');

describe('audience matching', function() {
  it('should flexibly match without regress', function(done) {
    var tests = {
      'http://fakesite.com and http://fakesite.com:80': true,
      'https://fakesite.com and https://fakesite.com:443': true,
      'http://fakesite.com:8000 and http://fakesite.com:8000': true,
      'https://fakesite.com:9000 and https://fakesite.com:9000': true,

      'http://fakesite.com:8100 and http://fakesite.com:80': false,
      'https://fakesite.com:9100 and https://fakesite.com:443': false,
      'http://fakesite.com:80 and http://fakesite.com:8000': false,
      'https://fakesite.com:443 and https://fakesite.com:9000': false,

      'app://browser.gaiamobile.org and app://browser.gaiamobile.org:80': true,

      'http://example.com:8080 and example.com:8080': true,
      'http://example.com:8080 and example.com': true
    };

    Object.keys(tests).forEach(function(test) {
      var origins = test.split(' and ');
      var err = compareAudiences(origins[0], origins[1]);
      if (tests[test]) {
        should.not.exist(err);
      } else {
        should.exist(err);
      }
    });

    done();
  });

  it('should catch malformed domains', function(done) {
    compareAudiences("http://example.com", "example.com::80");
    done();
  });

  it('should err on empty domains', function(done) {
    compareAudiences("http://example.com", "");
    done();
  });

  it('should catch mismatched schemes', function(done) {
    compareAudiences("http://example.com", "https://example.com");
    done();
  });

  it('should catch mismatched domains', function(done) {
    compareAudiences("http://example.com", "http://foo.example.com");
    done();
  });
});
