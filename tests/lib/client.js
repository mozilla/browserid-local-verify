/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* An abstraction around a client with a single identity. */

/* jshint curly: false */

const
async = require('async'),
jwcrypto = require('browserid-crypto');

require("browserid-crypto/lib/algs/rs");
require("browserid-crypto/lib/algs/ds");

function Client(args) {
  if (!args) args = {};
  this.args = args;
  this.args.idp = args.idp;
  this.args.email = args.email || 'test@' + args.idp.domain();
  this.args.algorithm = this.args.algorithm || "DS";
  this.args.keysize = this.args.keysize || 128;
  this.args.delegation = this.args.delegation || null;

  // allow algorithm specification as (i.e.) 'rs' or 'RS'
  this.args.algorithm = this.args.algorithm.toUpperCase();
}

function later(cb /* args */) {
  var args = Array.prototype.slice.call(arguments, 1);
  process.nextTick(function() {
    cb.apply(null, args);
  });
}

Client.prototype.email = function(arg) {
  if (arg !== undefined) this.args.email = arg;
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

    var params = {
      publicKey: self._publicKey,
    };

    if (self.args.email) {
      params.sub = self.args.email;
    }
    if (self.args.principal) {
      params.principal = self.args.principal;
    }

    jwcrypto.cert.sign(
      params,
      {
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

    // NOTE: historically assertions have not contained issuedAt, but jwcrypto
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

// generate an assertion with two certificates that is otherwise valid
Client.prototype.chainedAssertion = function(args, cb) {
  var self = this;

  var issuedAt = (self.args.certificateIssueTime * 1000) || new Date().getTime();
  var expiresAt = (issuedAt + (self.args.certificateDuration || 60 * 60));

  jwcrypto.generateKeypair({
    algorithm: self.args.algorithm,
    keysize: self.args.keysize
  }, function(err, kp) {
    if (err) return cb(err);
    var pubKey1 = kp.publicKey;
    var secKey1 = kp.secretKey;

    jwcrypto.cert.sign({
      publicKey: pubKey1,
      principal: { email: self.args.email }
    }, {
      issuer: self.args.idp.domain(),
      issuedAt: issuedAt,
      expiresAt:  expiresAt
    }, args.claims, self.args.idp.privateKey(), function(err, cert) {
      var cert1 = cert; // signed by the IdP

      jwcrypto.generateKeypair({
        algorithm: self.args.algorithm,
        keysize: self.args.keysize
      }, function(err, kp) {
        if (err) return cb(err);
        var pubKey2 = kp.publicKey;
        var secKey2 = kp.secretKey;

        jwcrypto.cert.sign({
          publicKey: pubKey2,
          principal: { email: 'bogus@example.com' }
        }, {
          issuer: self.args.email,
          issuedAt: issuedAt,
          expiresAt:  expiresAt
        }, args.claims, secKey1, function(err, cert) {
          var cert2 = cert; // signed by the key that was signed by the IdP

          self.certificate(function(err) {
            if (err) return cb(err);

            jwcrypto.assertion.sign(
              {}, { audience: args.audience, expiresAt: expiresAt },
              secKey2,
              function(err, signedContents) {
                if (err) return cb(err);
                var assertion = jwcrypto.cert.bundle([cert1, cert2], signedContents);
                cb(null, assertion);
              });
          });
        });
      });
    });
  });


};

module.exports = Client;
