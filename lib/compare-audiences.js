/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const
url = require('url');

// compare two audiences:
//   *want* is what was extracted from the assertion (it's trusted, we
//   generated it!
//   *got* is what was provided by the RP, so depending on their implementation
//   it might be strangely formed.
function compareAudiences(want, got) {
  function normalizeParsedURL(u) {
    // return object because url.parse returns object
    if (!u.port) {
      u.port = u.protocol === 'https:' ? '443' : '80';
    }
    return u;
  }

  try {
    var got_protocol, got_hostname, got_port;

    // We allow the RP to provide audience in multiple forms (see issue #82).
    // The RP SHOULD provide full origin, but we allow these alternate forms for
    // some dude named Postel doesn't go postal.
    // 1. full origin 'http://rp.tld'
    // 1a. full origin with port 'http://rp.tld:8080'
    // 2. domain and port 'rp.tld:8080'
    // 3. domain only 'rp.tld'

    // (app:// urls are seen on FirefoxOS desktop and possibly mobile)
    var gu = normalizeParsedURL(url.parse(got));
    if (gu.protocol !== 'https:' && gu.protocol !== 'http:' && gu.protocol !== 'app:') {
      // cases 2 & 3 default to http
      gu = normalizeParsedURL(url.parse('http://' + got));
    }
    got_protocol = gu.protocol;
    got_hostname = gu.hostname;
    got_port = gu.port;

    // now parse "want" url
    want = normalizeParsedURL(url.parse(want));

    if (got_protocol !== want.protocol) {
      throw new Error("scheme mismatch");
    }
    if (got_port !== want.port) {
      throw new Error("port mismatch");
    }
    if (got_hostname !== want.hostname) {
      throw new Error("domain mismatch");
    }

    return undefined;
  } catch(e) {
    return e.toString();
  }
}

module.exports = compareAudiences;
