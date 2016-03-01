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

  return authority;
}

module.exports.validateAuthority = validateAuthority;

function validateUrl(url) {
  var port;
  url = urlparse(url);
  if (!url.protocol) {
    throw new Error("invalid url: missing protocol");
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error("invalid url: unsupported scheme: " + url.protocol);
  }
  if (!url.hostname) {
    throw new Error("invalid url: missing hostname");
  }
  if (url.port) {
    // url.parse ensurses the port is a str repr of a positive integer.
    port = parseInt(url.port);
    if (port <= 0 || port >= 65536) {
      throw new Error("invalid url: port out of range: " +this.port);
    }
  }
  return {
    // remove trailing ":"
    scheme: url.protocol.slice(0, url.protocol.length - 1),
    host: url.hostname,
    port: url.port ? port : undefined,
    path: url.pathname
  };
}

module.exports.validateUrl = validateUrl;

function validateUrlPath(path) {
  if (path[0] !== '/') {
    throw new Error("invalid path: must start with a slash");
  }
  if (path !== validateUrl("http://example.com" + path).path) {
    throw new Error("invalid path");
  }
  return path;
}

module.exports.validateUrlPath = validateUrlPath;
