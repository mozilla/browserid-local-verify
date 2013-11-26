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

// a list of reserved claims including registered names
// from the jwt spec and browserid reserved (but "private")
// claims.
const reservedClaimNames = [
  'iss',
  'sub',
  'aud',
  'exp',
  'nbf',
  'iat',
  'jti',
  'public-key',
  'principal'
];

// given a payload (from assertion or certificate), extract
// "extra" claims embedded therein.  To conform with JWT, these are
// assumed to be un-recognized top level properties.  A historical exception
// is 'principal'.  If principal is an object, all claims other than 'email'
// will be extracted and returned as if they were proper top level jwt
// extensions.
function extractExtraClaims(claims) {
  var extraClaims = {};
  Object.keys(claims).forEach(function(key) {
    if (reservedClaimNames.indexOf(key) === -1) {
      extraClaims[key] = claims[key];
    }
  });
  // now extract unknown fields from 'principal' object as if they
  // were proper top level extensions
  if (typeof claims.principal === 'object') {
    Object.keys(claims.principal).forEach(function(key) {
      // only overlay non-reserved, non 'email', embedded claims
      // that do not exist at the top level.
      if (reservedClaimNames.indexOf(key) === -1 &&
          key !== 'email' &&
          !extraClaims[key]) {
        extraClaims[key] = claims.principal[key];
      }
    });
  }
  return Object.keys(extraClaims).length ? extraClaims : null;
}

function extractDomainFromEmail(email) {
  return (/\@(.*)$/).exec(email)[1].toLowerCase();
}

function verify(browserid, args, cb) {
  if (arguments.length !== 3) {
    throw "wrong number of arguments";
  }
  if (!args.assertion) {
    throw "missing required 'assertion' argument";
  }
  if (!args.audience) {
    throw "missing required 'audience' argument";
  }

  var assertion = args.assertion;
  var audience = args.audience;

  var ultimateIssuer;

  // we will manually unpack the certificate (IdP issued) and assertion
  // (UA generated).  jwcrypto's API's are insufficient to allow us to relay
  // claims made by each back to the user, which limits extensibility.
  var idpClaims, uaClaims;

  // first we must determine the principal email that this assertion vouches for.
  // BrowserID support document lookup requires that support documents are fetched
  // with the domain of the principal email to allow IdP's to serve dynamic
  // support documents.
  var principalDomain = null;
  try {
    var email = null;
    var bundle = jwcrypto.cert.unbundle(assertion);
    // idp's claims come from the last certificate in the chain.
    idpClaims = jwcrypto.extractComponents(bundle.certs[bundle.certs.length - 1]).payload;
    uaClaims = jwcrypto.extractComponents(bundle.signedAssertion).payload;
    if (idpClaims.principal) {
      email = idpClaims.principal.email;
    }
    if (!email) {
      email = idpClaims.sub;
    }
    principalDomain = extractDomainFromEmail(email);
  } catch(e) {
    // if we fail to extract principle domain, we will rely on subsequent verification
    // logic to determine whether this is an assertion *without* an email, and if it
    // can be trusted...
  }

  jwcrypto.cert.verifyBundle(
    assertion,
    args.now || new Date(),
    function(issuer, next) {
      // update issuer with each issuer in the chain, so the
      // returned issuer will be the last cert in the chain
      ultimateIssuer = issuer;

      // let's go fetch the public key for this issuer
      browserid.lookup({
        domain: issuer,
        principalDomain: principalDomain
      } , function(err, details) {
        if (err) {
          return cb(err);
        }
        next(null, details.publicKey);
      });
    }, function(err, certParamsArray, payload, assertionParams) {
      if (err) {
        return cb(err);
      }

      // for now, to be extra safe, we don't allow cert chains
      if (certParamsArray.length > 1) {
        return cb("certificate chaining is not yet allowed");
      }

      // audience must match!
      err = compareAudiences(assertionParams.audience, audience);
      if (err) {
        return cb("audience mismatch: " + err);
      }

      // build up a response object
      var obj = {
        audience: assertionParams.audience,
        expires: assertionParams.expiresAt,
        issuer: ultimateIssuer
      };

      if (idpClaims && idpClaims.principal && idpClaims.principal.email) {
        obj.email = idpClaims.principal.email;
      }

      // extract extra idp claims
      var extClaims = extractExtraClaims(idpClaims);
      if (extClaims) {
        obj.idpClaims = extClaims;
      }

      // extract extra ua claims
      extClaims = extractExtraClaims(uaClaims);
      if (extClaims) {
        obj.uaClaims = extClaims;
      }

      // If the caller has expressed trust in a set of issuers, then we need not verify
      // that those issuers can speak for the principal.
      if (args.trustedIssuers && args.trustedIssuers.indexOf(ultimateIssuer) !== -1) {
        cb(null, obj);
      }
      // otherwise, if there is an email embedded in the assertion, we must lookup the
      // expected issuer (by the BrowserID protocol) for that email domain.
      else if (principalDomain) {
        browserid.lookup({
          domain: principalDomain,
          principalDomain: principalDomain
        }, function(err, details) {
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
      // if there is no email in the assertion, and the issuer matches no-one we explicitly
      // trusted, then we can't trust this assertion.
      else {
        cb("untrusted assertion, doesn't contain an email, and issuer is untrusted ");
      }
    });
}

module.exports = verify;
