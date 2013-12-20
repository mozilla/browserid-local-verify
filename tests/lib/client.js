/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* An abstraction around a client with a single identity. */

/* jshint curly: false */

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

Client.prototype.email = function() {
  return this.args.email || null;
};

// generate or return a signed certificate for this client
Client.prototype.certificate = function(args, cb) {
  if (arguments.length === 1) {
    cb = args;
    args = {};
  }
  if (this._certificate) return later(cb, null, this._certificate);
  var self = this;

  jwcrypto.generateKeypair({
    algorithm: self.args.algorithm,
    keysize: self.args.keysize
  }, function(err, kp) {
    if (err) return cb(err);
    self._publicKey = kp.publicKey;
    self._secretKey = kp.secretKey;

    // allow the client to control issue time
    var issuedAt = (self.args.certificateIssueTime * 1000) || new Date().getTime();
    // cert valid for client specified duration or 60 minutes by default
    var expiresAt = (issuedAt + (self.args.certificateDuration || 60 * 60));

    var subject = self.args.principal ? self.args.principal.email : self.args.email;

    jwcrypto.cert.sign({
      publicKey: self._publicKey,
      sub: subject
    }, {
      issuer: self.args.idp.domain(),
      issuedAt: issuedAt,
      expiresAt:  expiresAt
    }, args.claims, self.args.idp.privateKey(), function(err, cert) {
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

    // NOTE: historically assertions have not contained issuedAt, but jwcrtpto
    // will check it if provided.  we hope it becomes part of the spec and test
    // here.
    var issuedAt = (args.issueTime * 1000) || new Date().getTime();
    var expiresAt = (issuedAt + (2 * 60 * 1000));
    jwcrypto.assertion.sign(
      {}, { audience: args.audience, expiresAt: expiresAt, issuedAt: issuedAt },
      self._secretKey,
      function(err, signedContents) {
        if (err) return cb(err);
        var assertion = jwcrypto.cert.bundle([self._certificate], signedContents);
        cb(null, assertion);
      });
  });
};

module.exports = Client;
