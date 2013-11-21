/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

var util = require("util");
var events = require("events");

function Verifier(args) {
  events.EventEmitter.call(this);
  this.args = augmentArguments(args);
}

// augment passed in arguments with library defaults
function augmentArguments(args) {
  if (!args) args = {};

  var newArgs = {
    'maxDelegations': 5,
    'httpTimeout': 10.0,
    'insecureSSL': false
  };

  Object.keys(args).forEach(function(k) {
    newArgs[k] = args[k];
  });

  return newArgs;
}

util.inherits(Verifier, events.EventEmitter);

var lookup = require('./lib/lookup.js');
Verifier.prototype.lookup = function(domain, principalDomain, cb) {
  lookup(this.args, this, domain, principalDomain, cb);
};

var verify = require('./lib/verify.js');
Verifier.prototype.verify = function(assertion, audience, cb) {
  verify(this.args, this, assertion, audience, cb);
};

module.exports = Verifier;

module.exports.lookup = function(args, domain, principalDomain, cb) {
  // support ommission of args param
  if (arguments.length === 2) {
    cb = principalDomain;
    principalDomain = domain;
    domain = args;
    args = null;
  }
  var v = new Verifier(args);
  v.lookup(domain, principalDomain, cb);
};

module.exports.verify = function(args, assertion, audience, cb) {
  // support ommission of args param
  if (arguments.length === 3) {
    cb = audience;
    audience = assertion;
    assertion = args;
    args = null;
  }
  var v = new Verifier(args);
  v.verify(assertion, audience, cb);
};
