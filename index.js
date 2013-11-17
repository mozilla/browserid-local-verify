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
Verifier.prototype.lookup = function(domain, cb) {
  lookup(this.args, this, domain, cb);
};

var verify = require('./lib/verify.js');
Verifier.prototype.verify = function(assertion, audience, cb) {
  verify(this.args, this, assertion, audience, cb);
};

module.exports = Verifier;

module.exports.lookup = function(args, domain, cb) {
  // support ommission of args param
  if (arguments.length === 2) {
    cb = domain;
    domain = args;
    args = null;
  }
  var v = new Verifier(args);
  v.lookup(domain, cb);
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
