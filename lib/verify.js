/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const
http = require("http"),
https = require("https"),
url = require("url"),
jwcrypto = require("jwcrypto"),
urlparse = require('urlparse'),
compareAudiences = require('./compare-audiences.js'),
util = require('util');

require("jwcrypto/lib/algs/ds");
require("jwcrypto/lib/algs/rs");

function extractDomainFromEmail(email) {
  return (/\@(.*)$/).exec(email)[1].toLowerCase();
}

// XXX document me!
// XXX allow variation of paramters on a per-call basis
function verify(args, browserid, assertion, audience, cb) {
  var ultimateIssuer;

  // first we must determine the principal email that this assertion vouches for.
  // BrowserID support document lookup requires that support documents are fetched
  // with the domain of the principal email to allow IdP's to serve dynamic
  // support documents.
  var principalDomain = null;
  try {
    var email = null;
    var bundle = jwcrypto.cert.unbundle(assertion);
    // principal will be in the last certificate in the chain.
    var payload = jwcrypto.extractComponents(bundle.certs[bundle.certs.length - 1]).payload;
    if (payload.principal) email = payload.principal.email;
    if (!email) email = payload.sub;
    principalDomain = extractDomainFromEmail(email);
  } catch(e) {
    // if we fail to extract principle domain, we will rely on subsequent verification
    // logic to determine whether this is an assertion *without* an email, and if it
    // can be trusted...
  }

  // XXX: make verification time configurable.  Allow the caller to pass in the
  // time for which the assertion should be checked for validity, and in the absence
  // of that, let's use current javascript time.
  //
  // This facilitates testing.
  jwcrypto.cert.verifyBundle(
    assertion,
    args.now || new Date(),
    function(issuer, next) {
      // update issuer with each issuer in the chain, so the
      // returned issuer will be the last cert in the chain
      ultimateIssuer = issuer;

      // let's go fetch the public key for this host
      browserid.lookup(issuer, principalDomain, function(err, details) {
        if (err) return cb(err);
        next(null, details.publicKey);
      });
    }, function(err, certParamsArray, payload, assertionParams) {
      if (err) return cb(err);

      // for now, to be extra safe, we don't allow cert chains
      if (certParamsArray.length > 1) {
        return cb("certificate chaining is not yet allowed");
      }

      // audience must match!
      err = compareAudiences(assertionParams.audience, audience);
      if (err) {
        return cb("audience mismatch: " + err);
      }

      // principal is in the last certificate
      var principal = certParamsArray[certParamsArray.length - 1].certParams.principal;

      // build up a response object
      var obj = {
        audience: assertionParams.audience,
        expires: assertionParams.expiresAt,
        issuer: ultimateIssuer
      };

      if (principal.email) obj.email = principal.email;

      // XXX: include other signed information from ceritificate and assertion

      // If the caller has expressed trust in a set of issuers, then we need not verify
      // that those issuers can speak for the principal.
      if (args.trustedIssuers && args.trustedIssuers.indexOf(ultimateIssuer) !== -1) {
        cb(null, obj);
      }
      // otherwise, if there is an email embedded in the assertion, we must lookup the
      // expected issuer (by the BrowserID protocol) for that email domain.
      else if (principalDomain) {
        browserid.lookup(principalDomain, principalDomain, function(err, details) {
          var expectedIssuer = args.fallback;
          if (!err && details.authoritativeDomain) {
            expectedIssuer = details.authoritativeDomain;
          }
          if (expectedIssuer !== ultimateIssuer) {
            cb(util.format("untrusted issuer, expected '%s', got '%s'",
                           expectedIssuer, ultimateIssuer));
          } else {
            cb(null, obj);
          }
        });
      }
      // otherwise, if there is an email embedded in the assertion, we must lookup the
      // expected issuer (by the BrowserID protocol) for that email domain.
      else {
        cb("untrusted assertion, doesn't contain an email, and issuer is untrusted ");
      }
    });
}

module.exports = verify;
