/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* An abstraction around a client with a single identity. */

const
async = require('async'),
jwcrypto = require('jwcrypto');

require("jwcrypto/lib/algs/rs");
require("jwcrypto/lib/algs/ds");

function Client(args) {
  if (!args) args = {};
  this.args = args;
  this.args.idp = args.idp;
  this.args.email = args.email || 'test@' + args.idp.domain();
  this.args.algorithm = this.args.algorithm || "dsa";
  this.args.keysize = this.args.keysize || 128;
  this.args.delegation = this.args.delegation || null;

  // allow algorithm specification as (i.e.) 'rsa' or 'RS'
  this.args.algorithm = this.args.algorithm.toUpperCase().substr(0,2);
}

function later(cb /* args */) {
  var args = Array.prototype.slice.call(arguments, 1);
  process.nextTick(function() {
    cb.apply(null, args);
  });
}

// generate or return a signed certificate for this client
Client.prototype.certificate = function(cb) {
  if (this._certificate) return later(null, this._certificate);
  var self = this;

  jwcrypto.generateKeypair({
    algorithm: self.args.algorithm,
    keysize: self.args.keysize
  }, function(err, kp) {
    if (err) return cb(err);
    self._publicKey = kp.publicKey;
    self._secretKey = kp.secretKey;
    jwcrypto.cert.sign({
      publicKey: self._publicKey,
      principal: { email: self.args.email }
    }, {
      issuer: self.args.idp.domain(),
      issuedAt: new Date(),
      expiresAt: (new Date() + (60 * 60)) // cert valid for 60 minutes
    }, null, self.args.idp.privateKey(), function(err, cert) {
      self._certificate = cert;
      cb(err, cert);
    });
  });
};

// generate an assertion (and keypair and signed cert if required)
Client.prototype.assertion = function(args, cb) {
  var self = this;
  self.certificate(function(err) {
    if (err) return cb(err);
    jwcrypto.assertion.sign(
      {}, { audience: args.audience, expiresAt: (new Date() + 120) },
      self._secretKey,
      function(err, signedContents) {
        if (err) return cb(err);
        var assertion = jwcrypto.cert.bundle([self._certificate], signedContents);
        cb(null, assertion);
      });
  });
};


module.exports = Client;
