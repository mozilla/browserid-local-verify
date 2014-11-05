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
async = require('async'),
https = require('https'),
fs = require('fs'),
jwcrypto = require('browserid-crypto'),
path = require('path');

// I hate this.
require("browserid-crypto/lib/algs/rs");
require("browserid-crypto/lib/algs/ds");

function IdP(args) {
  if (!args) args = {};
  this.args = args;
  // default paramter values
  this.args.delay = this.args.delay || 0;
  this.args.algorithm = this.args.algorithm || "RS";
  this.args.keysize = this.args.keysize || 128;
  this.args.delegation = this.args.delegation || null;

  // allow algorithm specification as (i.e.) 'rs' or 'RS'
  this.args.algorithm = this.args.algorithm.toUpperCase();

  if (args.wellKnown) this.wellKnown(args.wellKnown);
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
  if (!this._started) throw "IdP isn't started, it has no public key";
  return this.details.publicKey;
};

IdP.prototype.privateKey = function() {
  if (!this._started) throw "IdP isn't started, it has no public key";
  return this._secretKey;
};

IdP.prototype.domain = function() {
  if (!this._started) throw "IdP isn't started, it has no domain";
  return this.details.domain;
};

// the domain to whom this domain should delegate
IdP.prototype.delegation = function(domain) {
  if (domain === null) this.args.delegation = null;
  return (this.args.delegation = domain || this.args.delegation);
};

IdP.prototype.delay = function(delay) {
  if (typeof delay === 'number') this.args.delay = delay;
  return this.args.delay;
};

IdP.prototype.wellKnown = function(obj) {
  if (obj !== undefined) this.args.wellKnown = obj;
  return this.args.wellKnown || {
    authentication: '/auth.html',
    provisioning: '/prov.html',
    "public-key": this.publicKey().toSimpleObject()
  };
};


IdP.prototype.start = function(cb) {
  if (this._started) return later(cb, null, this.details);
  this._started = true;

  var self = this;

  function handleRequest(req, res) {
    if (req.url.indexOf('/.well-known/browserid') !== 0) {
      return res.send(404);
    }

    // XXX: these config values should all be mutually exclusive.  There's this odd
    // precedence going on that will confuse some poor test writer.
    if (self.args.http_redirect) {
      var location = 'https://' + self.args.http_redirect + '/.well-known/browserid';
      res.writeHead(301, {'Location': location});
      res.end();
    } else if (self.args.disabled) {
      res.writeHead(200, {'Content-Type': 'application/json'});
      res.end(JSON.stringify({disabled: true}));
    } else if (self.args.delegation) {
      res.writeHead(200, {'Content-Type': 'application/json'});
      res.end(JSON.stringify({authority: self.args.delegation}));
    }
    // if the caller supplied a 'dynamicWellKnown' function, allow them to
    // craft a support document after considering the URL with which it was
    // fetched
    else if (self.args.dynamicWellKnown) {
      self.args.dynamicWellKnown(req.url, function(err, doc) {
        if (err) {
          res.writeHead(500, {'Error': err});
        } else {
          res.writeHead(200, {'Content-Type': 'application/json'});
          res.end(JSON.stringify(doc || self.wellKnown()));
        }
      });
    } else {
      res.writeHead(200, {'Content-Type': 'application/json'});
      res.end(JSON.stringify(self.wellKnown()));
    }
  }

  async.parallel([
    function(cb) {
      // spin up an HTTPS server bound to an ephemeral port
      // using self signed certificates
      self._server = https.createServer({
        key: fs.readFileSync(path.join(__dirname, '..', 'resources', 'key.pem')),
        cert: fs.readFileSync(path.join(__dirname, '..', 'resources', 'cert.pem'))
      }, function (req, res) {
        setTimeout(function() {
          handleRequest(req, res);
        }, self.args.delay * 1000);
      }).listen(0, '127.0.0.1', function() {
        cb(null);
      });
    },
    function(cb) {
      // generate an RSA keypair for the idp
      jwcrypto.generateKeypair({
        algorithm: self.args.algorithm,
        keysize: self.args.keysize
      }, function(err, kp) {
        if (err) return cb(err);
        self._publicKey = kp.publicKey;
        self._secretKey = kp.secretKey;
        cb(null);
      });
    }
  ], function(err) {
    var addy = self._server.address();
    var domain = addy.address + ":" + addy.port;
    self.details = {
      url: "https://" + domain + "/",
      domain: domain,
      publicKey: self._publicKey
    };
    cb(err, self.details);
  });
};

IdP.prototype.stop = function(cb) {
  if (!this._started) return later(cb, null);
  else this._server.close(cb);
};

module.exports = IdP;
