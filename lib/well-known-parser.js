/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

var jwcrypto = require("browserid-crypto");
var validation = require('./validation.js');

// parse a well-known document.  throw an exception if it is invalid, return
// a parsed version if it is valid.  return is an object having the following fields:
//   * 'type' - one of "disabled", "delegation", or "supported"
//   * if type is "delegation", also:
//     * authority - the domain authority is delegated to
//   * if type is "supported":
//     * publicKeys - a parsed representation of its list of published public keys
//     * publicKey - a parsed representation of its current public key
//     * paths.authentication - the path to the 'authentication' html
//     * paths.provisioning - the path to the 'provisioning' html
module.exports = function(doc) {
  try {
    doc = JSON.parse(doc);
  } catch(e) {
    throw new Error("declaration of support is malformed (invalid json)");
  }

  if (typeof doc !== 'object') {
    throw new Error("support document must contain a json object");
  }

  // there are three main types of support documents
  // 1. "supported" - declares the domain is a browserid authority,
  //    contains public keys, authentication, and provisioning
  // 2. "delegation" - declares the domain allows a different domain
  //    to be authoritative for it.
  // 3. "disable" - domain declares explicitly that it wants a secondary
  //    to be authoritative.

  // is this a "disable" document?
  if (doc.disabled === true) {
    return { type: "disabled" };
  } else if (doc.disabled !== undefined && doc.disabled !== false) {
    throw new Error("disabled must be either true or false");
  }

  // is this a delegation document?
  if (doc.authority) {
    if (typeof doc.authority !== 'string') {
      throw new Error("malformed authority");
    }
    try {
      validation.validateAuthority(doc.authority);
    } catch (e) {
      throw new Error("the authority is not a valid hostname");
    }

    return {
      type: "delegation",
      authority: doc.authority
    };
  }

  // is this a support document?

  // the response that we'll populate as we go
  var parsed = {
    type: "supported",
    paths: {},
    publicKeys: [],
    publicKey: null
  };

  [ 'authentication', 'provisioning' ].forEach(function(requiredKey) {
    if (typeof doc[requiredKey] !== 'string') {
      throw new Error("support document missing required property: '" + requiredKey + "'");
    } else {
      validation.validateUrlPath(doc[requiredKey]);
      parsed.paths[requiredKey] = doc[requiredKey];
    }
  });

  // For backwards-compat reasons, the support document can contain
  // one or both of:
  //  * a single current public key in 'public-key'
  //  * a list of acceptable public keys in 'keys'

  if (doc['public-key']) {
    try {
      parsed.publicKey = jwcrypto.loadPublicKeyFromObject(doc['public-key']);
    } catch(e) {
      throw new Error("mal-formed public key in support doc: " + e.toString());
    }
    parsed.publicKeys.push(parsed.publicKey);
  }

  if (doc.keys) {
    if (!Array.isArray(doc.keys)) {
      throw new Error("mal-formed list of public keys in support doc");
    }
    doc.keys.forEach(function(key) {
      try {
        // Ensure only keys meant for signing are included in the list.
        if (!key.use || key.use === 'sig') {
          parsed.publicKeys.push(jwcrypto.loadPublicKeyFromObject(key));
        }
      } catch(e) {
        throw new Error("mal-formed public key in support doc: " + e.toString());
      }
    });
  }

  if (parsed.publicKeys.length === 0) {
    throw new Error("support document missing required property 'keys' and/or 'public-key'");
  }
  if (!parsed.publicKey) {
    parsed.publicKey = parsed.publicKeys[0];
  }

  // success!
  return parsed;
};
