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
    // return string because url.parse returns string
    if (!u.port) u.port = u.protocol === 'https:' ? '443' : '80';
    return u;
  }

  try {
    var got_scheme, got_domain, got_port;

    // We allow the RP to provide audience in multiple forms (see issue #82).
    // The RP SHOULD provide full origin, but we allow these alternate forms for
    // some dude named Postel doesn't go postal.
    // 1. full origin 'http://rp.tld'
    // 1a. full origin with port 'http://rp.tld:8080'
    // 2. domain and port 'rp.tld:8080'
    // 3. domain only 'rp.tld'

    // case 1 & 1a
    // (app:// urls are seen on FirefoxOS desktop and possibly mobile)
    if (/^(?:https?|app):\/\//.test(got)) {
      var gu = normalizeParsedURL(url.parse(got));
      got_scheme = gu.protocol;
      got_domain = gu.hostname;
      got_port = gu.port;
    }
    // case 2
    else if (got.indexOf(':') !== -1) {
      var p = got.split(':');
      if (p.length !== 2) throw "malformed domain";
      got_domain = p[0];
      got_port = p[1];
    }
    // case 3
    else {
      got_domain = got;
    }
    if (!got_domain) throw "domain missing";

    // now parse "want" url
    want = normalizeParsedURL(url.parse(want));

    // compare the parts explicitly provided by the client
    if (got_scheme && got_scheme !== want.protocol) throw "scheme mismatch";
    if (got_port && got_port !== want.port) throw "port mismatch";
    if (got_domain !== want.hostname) throw "domain mismatch";

    return undefined;
  } catch(e) {
    return e.toString();
  }
}

module.exports = compareAudiences;
