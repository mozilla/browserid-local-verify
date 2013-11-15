/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const
async = require('async'),
https = require('https'),
fs = require('fs'),
jwcrypto = require('jwcrypto'),
path = require('path');

// I hate this.
require("jwcrypto/lib/algs/rs");
require("jwcrypto/lib/algs/ds");

function Secondary(args) {
  this.args = args;
}

function later(self, cb /* args */) {
  process.nextTick(function() {
    cb.apply(null, arguments.slice(2));
  });
}

Secondary.prototype.start = function(cb) {
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
        console.log("a");
        res.writeHead(200, {'Content-Type': 'text/plain'});
        res.end('Hello World\n');
      }).listen(0, '127.0.0.1', function() {
        console.log(self._server);
        cb(null);
      });
    },
    function(cb) {
      // generate an RSA keypair for the idp
      jwcrypto.generateKeypair({ algorithm: 'RS', keysize: '128' }, function(err, kp) {
        console.log("b");

        if (err) return cb(err);
        self._publicKey = kp.publicKey;
        self._secretKey = kp.secretKey;
        cb(null);
      });
    }
  ], function(err) {
    self.details = {
    };
    cb(err, self.details);
  });
};

exports.Secondary = Secondary;
