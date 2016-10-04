/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* This file contains a test identity provider (IdP).  An IdP consists of,
 * for the purposes of testing verification, an SSL server (with self signed
 * certificate), and a keypair.  The servers are bound on ephemeral ports and
 * will be programatically configurable.  This allows us to robustly test
 * delegation chains, signing, and a whole bunch of other features implemented
 * by the verification library.
 */

/* jshint curly: false */

const
url = require('url'),
http = require('http'),
https = require('https');


function Proxy() {
}

function later(cb /* args */) {
  var args = Array.prototype.slice.call(arguments, 1);
  process.nextTick(function() {
    cb.apply(null, args);
  });
}

Proxy.prototype.url = function() {
  if (!this._started) throw "Proxy isn't started, it has no url";
  return this.details.url;
};

Proxy.prototype.numRequests = function() {
  if (!this._started) throw "Proxy isn't started, it has no numRequests";
  return this.details.numRequests;
};

Proxy.prototype.clearNumRequests = function() {
  if (!this._started) throw "Proxy isn't started, it has no numRequests";
  this.details.numRequests = 0;
};

Proxy.prototype.start = function(cb) {
  if (this._started) return later(cb, null, this.details);
  this._started = true;

  var self = this;

  function handleRequest(req, res) {
    self.details.numRequests += 1;
    if (req.method !== 'GET') {
      res.writeHead(405);
      return res.end();
    }
    var proxyOptions = url.parse(req.url);
    proxyOptions.headers = req.headers;
    proxyOptions.rejectUnauthorized = false;
    var proxyReq = https.request(proxyOptions, function(proxyRes) {
      var body = "";
      proxyRes.on('data', function(chunk) { body += chunk; });
      proxyRes.on('end', function() {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        res.write(body);
        res.end();
      });
    });
    proxyReq.end();
  }

  // Listen on a plain http port as a local proxy.
  self._server = http.createServer(function (req, res) {
    setTimeout(function() {
      handleRequest(req, res);
    }, 1);
  }).listen(0, '127.0.0.1', function() {
    var addy = self._server.address();
    var domain = addy.address + ":" + addy.port;
    self.details = {
      url: "http://" + domain + "/",
      numRequests: 0,
    };
    cb(null, self.details);
  });
};

Proxy.prototype.stop = function(cb) {
  if (!this._started) return later(cb, null);
  else this._server.close(cb);
};

module.exports = Proxy;
