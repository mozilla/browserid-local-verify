/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const urlparse = require('url').parse;

function validateAuthority(authority) {
  // canary values
  const scheme = 'https:';
  const directory = '/foo/';
  const file = 'bar.html';
  const query = 'q=blah';
  const anchor = 'content';

  var url = urlparse(scheme + "//" + authority + directory + file + '?' + query + '#' + anchor);
  if (url.protocol !== scheme ||
      url.host !== authority ||
      url.pathname !== directory + file ||
      url.search !== '?' + query ||
      url.hash !== '#' + anchor ||
      url.auth !== null) {
    throw new Error("invalid hostname");
  }
}

module.exports.validateAuthority = validateAuthority;
