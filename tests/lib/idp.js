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

const
async = require('async'),
https = require('https'),
fs = require('fs'),
jwcrypto = require('jwcrypto'),
path = require('path');

// I hate this.
require("jwcrypto/lib/algs/rs");
require("jwcrypto/lib/algs/ds");

function IdP(args) {
  this.args = args;
}

function later(cb /* args */) {
  var args = Array.prototype.slice.call(arguments, 1);
  process.nextTick(function() {
    cb.apply(null, args);
  });
}

IdP.prototype.url = function() {
  if (!this._started) throw "IdP isn't started, it has no url";
  return this.details.url;
};

IdP.prototype.publicKey = function() {
  if (!this._started) throw "IdP isn't started, it has no url";
  return this.details.publicKey;
};

IdP.prototype.start = function(cb) {
  if (this._started) return later(cb, null, this.details);
  this._started = true;

  var self = this;

  async.parallel([
    function(cb) {
      // spin up an HTTPS server bound to an ephemeral port
      // using self signed certificates
      self._server = https.createServer({
        key: fs.readFileSync(path.join(__dirname, '..', 'resources', 'key.pem')),
        cert: fs.readFileSync(path.join(__dirname, '..', 'resources', 'cert.pem'))
      }, function (req, res) {
        res.writeHead(200, {'Content-Type': 'text/plain'});
        res.end('Hello World\n');
      }).listen(0, '127.0.0.1', function() {
        cb(null);
      });
    },
    function(cb) {
      // generate an RSA keypair for the idp
      jwcrypto.generateKeypair({ algorithm: 'RS', keysize: '128' }, function(err, kp) {
        if (err) return cb(err);
        self._publicKey = kp.publicKey;
        self._secretKey = kp.secretKey;
        cb(null);
      });
    }
  ], function(err) {
    var addy = self._server.address();
    self.details = {
      url: "https://" + addy.address + ":" + addy.port + "/",
      publicKey: self._publicKey
    };
    cb(err, self.details);
  });
};

IdP.prototype.stop = function(cb) {
  if (!this._started) return later(cb, null);
  else this._server.close(cb);
};

exports.IdP = IdP;
