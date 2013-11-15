/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

var
https = require('https'),
wellKnownParser = require('./well-known-parser.js'),
urlparse = require('urlparse');

const WELL_KNOWN_URL = "/.well-known/browserid";

// hit the network and fetch a .well-known document in its unparsed form
var fetchWellKnown = function (args, emitter, currentDomain, principalDomain, clientCB) {
  // in many cases the http layer can send both an 'error' and an 'end'.  In
  // other cases, only 'error' will be emitted.  We want to
  // ensure the client callback is invoked only once.  this function does it.
  var startTime = new Date();
  var cb = function(err) {
    var reqTime = new Date() - startTime;

    if (err)
      emitter.emit('info', 'elapsed_time.fetch_well_known.error', {
        elapsed: reqTime
      });
    else
      emitter.emit('info', 'elapsed_time.fetch_well_known.success', {
        elapsed: reqTime
      });

    if (clientCB) {
      clientCB.apply(null, arguments);
      clientCB = null;
    }
  };

  function handleResponse(err, statusCode, headers, body) {
    if (statusCode !== 200) {
      if (Math.floor(statusCode / 100) === 3) {
        return cb(currentDomain +
                  ' is not a browserid primary - redirection not supported for support documents');
      } else {
        return cb(currentDomain +
                  ' is not a browserid primary - non-200 response code to ' +
                  WELL_KNOWN_URL);
      }
    }
    // favor Postel over node convention
    var contentType = headers['content-type'] || headers['Content-Type'] || headers['Content-type'];
    if (!contentType || contentType.indexOf('application/json') !== 0) {
      return cb(currentDomain +
                ' is not a browserid primary - non "application/json" response to ' +
                WELL_KNOWN_URL);
    }

    cb(null, body, currentDomain);
  }

  var pathToWellKnown = WELL_KNOWN_URL + "?domain=" + principalDomain;

  // If the client has provided a function to perform their own http requests,
  // use that.
  if (args.httpRequest) {
    return args.httpRequest(currentDomain, pathToWellKnown, handleResponse);
  } else {
    var port = 443;
    var host = currentDomain;
    // somewhat odd, but we do allow a host:port to be specified as a domain.
    // this supports local testing using the built in https implementation.
    if (currentDomain.indexOf(':') !== -1) {
      var s = currentDomain.split(':');
      host = s[0];
      port = s[1];
    }
    var req = https.get({
      host: host,
      port: port,
      path: pathToWellKnown,
      rejectUnauthorized: !args.insecureSSL,
      agent: false
    }, function(res) {
      var body = "";
      res.on('data', function(chunk) { body += chunk; });
      res.on('end', function() {
        handleResponse(null, res.statusCode, res.headers, body);
      });
    });

    // front-end shows xhr delay message after 10 sec; timeout sooner to avoid this
    var reqTimeout = setTimeout(function() {
      req.abort();
      return cb('timeout trying to load well-known for ' + currentDomain);
    }, args.httpTimeout * 1000);
    req.on('response', function() { clearTimeout(reqTimeout); });
    req.on('error', function(e) {
      if (reqTimeout) { clearTimeout(reqTimeout); }
      return cb(currentDomain + ' is not a browserid primary: ' + String(e));
    });
  }
};

// Fetch a .well-known file from the network, following delegation
function deepFetchWellKnown(args, emitter, principalDomain, cb, currentDomain, delegationChain) {
  // this function is recursive, the last two parameters are only specified
  // when invoking ourselves.
  if (!currentDomain) currentDomain = principalDomain;
  if (!delegationChain) delegationChain = [ principalDomain ];

  fetchWellKnown(args, emitter, currentDomain, principalDomain, function(err, unparsedDoc) {
    if (err) return cb(err);

    var supportDoc;
    try {
      supportDoc = wellKnownParser(unparsedDoc);
    } catch (e) {
      return cb("bad support document for '" + currentDomain + "': " + String(e));
    }

    if (supportDoc.type === 'disabled')
    {
      return cb(null, {
        disabled: true,
        delegationChain: delegationChain,
        authoritativeDomain: delegationChain[delegationChain.length - 1],
      });
    }
    else if (supportDoc.type === 'delegation')
    {
      currentDomain = supportDoc.authority;

      // check for cycles in delegation
      if (delegationChain.indexOf(currentDomain) !== -1) {
        return cb("Circular reference in delegating authority: " + delegationChain.join(" > "));
      }

      delegationChain.push(currentDomain);

      emitter.emit('info', delegationChain[delegationChain.length - 2] + " delegates to " +
                   delegationChain[delegationChain.length - 1]);

      // check for max delegation length
      if (delegationChain.length > args.maxDelegations) {
        return cb("Too many hops while delegating authority: " + delegationChain.join(" > "));
      }

      // recurse
      return deepFetchWellKnown(args, emitter, principalDomain, cb, currentDomain, delegationChain);
    }
    else if (supportDoc.type === 'supported')
    {
      var url_prefix = 'https://' + currentDomain;

      var details = {
        publicKey: supportDoc.publicKey,
        urls: {
          auth: url_prefix + supportDoc.paths.authentication,
          prov: url_prefix + supportDoc.paths.provisioning
        },
        delegationChain: delegationChain,
        authoritativeDomain: delegationChain[delegationChain.length - 1]
      };

      // validate the urls
      try {
        urlparse(details.urls.auth).validate();
        urlparse(details.urls.prov).validate();
      } catch(e) {
        return cb("invalid URLs in support document: " + e.toString());
      }

      // success!
      cb(null, details);
    }
    else
    {
      var msg = "unhandled error while parsing support document for " + currentDomain;
      return cb(msg);
    }
  });
}

module.exports = deepFetchWellKnown;
