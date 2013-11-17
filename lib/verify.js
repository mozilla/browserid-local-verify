/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const
http = require("http"),
https = require("https"),
url = require("url"),
jwcrypto = require("jwcrypto"),
urlparse = require('urlparse'),
compareAudiences = require('./compare-audiences.js');

require("jwcrypto/lib/algs/ds");
require("jwcrypto/lib/algs/rs");

const UNVERIFIED_EMAIL = 'unverified-email';

// verify the tuple certList, assertion, audience
//
// assertion is a bundle of the underlying assertion and the cert list
// audience is a web origin, e.g. https://foo.com or http://foo.org:81
// forceIssuer is a hostname or `undefined` for normal BID protocol
// allowUnverified is boolean to check for email or unverified-email
function verify(assertion, audience, forceIssuer, allowUnverified, successCB, errorCB) {
  // assertion is bundle
  var ultimateIssuer,
      verified = true;

  jwcrypto.cert.verifyBundle(
    assertion,
    new Date(), function(issuer, next) {
      // update issuer with each issuer in the chain, so the
      // returned issuer will be the last cert in the chain
      ultimateIssuer = issuer;

      // allow other retrievers for testing
      if (issuer === HOSTNAME) return next(null, publicKey);
      else if (config.get('disable_primary_support')) {
        return errorCB("this verifier doesn't respect certs issued from domains other than: " +
                       HOSTNAME);
      } else if (issuer === forceIssuer) {
        if (config.get('forcible_issuers').indexOf(forceIssuer) === -1) {
          return errorCB("this verifier won't force issuer for " + forceIssuer);
        } else {
          return next(null, publicKey);
        }
      }

      // XXX: this network work happening inside a compute process.
      // if we have a large number of requests to auth assertions that require
      // keyfetch, this could theoretically hurt our throughput.  We could
      // move the fetch up into the browserid process and pass it into the
      // compute process at some point.

      // let's go fetch the public key for this host
      primary.getPublicKey(issuer, function(err, pubKey) {
        if (err) return errorCB(err);
        next(null, pubKey);
      });
    }, function(err, certParamsArray, payload, assertionParams) {
      if (err) return errorCB(err);

      // for now, to be extra safe, we don't allow cert chains
      if (certParamsArray.length > 1)
        return errorCB("certificate chaining is not yet allowed");

      // audience must match!
      err = compareAudiences(assertionParams.audience, audience);
      if (err) {
        logger.debug("verification failure, audience mismatch: '"
                     + assertionParams.audience + "' != '" + audience + "': " + err);
        return errorCB("audience mismatch: " + err);
      }

      // principal is in the last cert
      var principal = certParamsArray[certParamsArray.length - 1].certParams.principal;

      // unverified assertions are only valid if they are expected
      if (principal[UNVERIFIED_EMAIL] && !allowUnverified) {
        return errorCB("unverified email");
      }

      // verify that the issuer is the same as the email domain or
      // that the email's domain delegated authority to the issuer
      var email = principal.email;
      if (allowUnverified && !email) {
        email = principal[UNVERIFIED_EMAIL];
        verified = false;
      }

      if (!email) {
        return errorCB("missing email");
      }

      var domainFromEmail = primary.domainFromEmail(email);

      if (ultimateIssuer !== HOSTNAME &&
          ultimateIssuer !== domainFromEmail &&
          ultimateIssuer !== forceIssuer)
      {
          primary.delegatesAuthority(domainFromEmail, ultimateIssuer, function (delegated) {
            if (delegated) {
              return successCB(email, assertionParams.audience, assertionParams.expiresAt, ultimateIssuer, verified);
            } else {
              return errorCB("issuer '" + ultimateIssuer + "' may not speak for emails from '"
                         + domainFromEmail + "'");
            }
          });
      } else {
        return successCB(email, assertionParams.audience, assertionParams.expiresAt, ultimateIssuer, verified);
      }
    }, errorCB);
}

exports.verify = verify;
