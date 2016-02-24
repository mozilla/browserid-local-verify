/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

var
dbug = require('dbug')('browserid-local-verify:lookup'),
http = require('http'),
https = require('https'),
validation = require('./validation.js'),
wellKnownParser = require('./well-known-parser.js');

const WELL_KNOWN_URL = "/.well-known/browserid";

const DEFAULT_PORTS = {
  'http': 80,
  'https': 443
};

// like https.get() but transparently supports the
// $https_proxy and $no_proxy environment variables.
var getWithTransparentProxying = function(options, cb) {
  var httpmod = https;
  var proxy = shouldUseProxy(options.host);
  if (proxy) {
    if (proxy.scheme === 'http') {
      httpmod = http;
    }
    if (!options.headers) {
      options.headers = {};
    }
    if (!options.headers.host) {
      options.headers.host = options.host;
    }
    options.path = 'https://' + options.host + ':' + options.port + options.path;
    options.host = proxy.host;
    options.port = proxy.port || DEFAULT_PORTS[proxy.scheme];
  }
  return httpmod.get(options, cb);
};

var shouldUseProxy = function(host) {
  // Check if we have a proxy configured for https urls.
  var httpsProxy = process.env.https_proxy || process.env.HTTPS_PROXY;
  if (!httpsProxy) {
    return null;
  }
  httpsProxy = validation.validateUrl(httpsProxy);
  // Check if this host is exclued via the no-proxy list.
  var noProxy = process.env.no_proxy || process.env.NO_PROXY;
  if (noProxy) {
    if (noProxy === '*') {
      return null;
    }
    var noProxyList = noProxy.split(/,\s*/);
    for (var i = 0; i < noProxyList.length; i++) {
      var suffix = noProxyList[i];
      if (host.lastIndexOf(suffix) === host.length - suffix.length) {
        return null;
      }
    }
  }
  // Yep, we need to use the proxy.
  return httpsProxy;
};


// hit the network and fetch a .well-known document in its unparsed form
var fetchWellKnown = function (emitter, args, currentDomain, principalDomain, clientCB) {
  // in many cases the http layer can send both an 'error' and an 'end'.  In
  // other cases, only 'error' will be emitted.  We want to
  // ensure the client callback is invoked only once.  this function does it.
  var startTime = new Date();
  var cb = function(err) {
    var reqTime = new Date() - startTime;

    dbug('metric.elapsed_time.fetch_well_known.%s: %d', (err ? 'error' : 'success'), reqTime);
    emitter.emit('metric',
                 'elapsed_time.fetch_well_known.' + (err ? 'error' : 'success'),
                 reqTime);

    if (clientCB) {
      clientCB.apply(null, arguments);
      clientCB = null;
    }
  };

  function handleResponse(err, statusCode, headers, body) {
    if (statusCode !== 200) {
      if ([301, 302, 303, 307].indexOf(statusCode) !== -1) {
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

  dbug('fetching well-known from "%s" for principal "%s"', currentDomain,
               principalDomain);

  // If the client has provided a function to perform their own http requests,
  // use that.
  if (args.httpRequest) {
    return args.httpRequest(currentDomain, pathToWellKnown, handleResponse);
  } else {
    var port = DEFAULT_PORTS.https;
    var host = currentDomain;
    // somewhat odd, but we do allow a host:port to be specified as a domain.
    // this supports local testing using the built in https implementation.
    if (currentDomain.indexOf(':') !== -1) {
      var s = currentDomain.split(':');
      host = s[0];
      port = s[1];
    }
    var req = getWithTransparentProxying({
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
    req.end();

    // front-end shows xhr delay message after 10 sec; timeout sooner to avoid this
    var reqTimeout = setTimeout(function() {
      req.abort();
      return cb('timeout trying to load well-known for ' + currentDomain);
    }, args.httpTimeout * 1000);
    req.on('response', function() {
      if (reqTimeout) {
        clearTimeout(reqTimeout);
        reqTimeout = null;
      }
    });
    req.on('error', function(e) {
      if (reqTimeout) {
        clearTimeout(reqTimeout);
        reqTimeout = null;
      }
      return cb(currentDomain + ' is not a browserid primary: ' + String(e));
    });
  }
};

// Fetch a .well-known file from the network, following delegation
function lookup(emitter, args, currentDomain, principalDomain, cb, delegationChain) {
  if (!currentDomain) {
    currentDomain = principalDomain;
  }
  if (!principalDomain) {
    principalDomain = currentDomain;
  }
  if (!delegationChain) {
    delegationChain = [ principalDomain ];
  }

  try {
    validation.validateAuthority(principalDomain);
  } catch (e) {
    return cb("invalid domain: " + principalDomain);
  }
  if (currentDomain !== principalDomain) {
    try {
      validation.validateAuthority(currentDomain);
    } catch (e) {
      return cb("invalid domain: " + currentDomain);
    }
  }

  fetchWellKnown(emitter, args, currentDomain, principalDomain, function(err, unparsedDoc) {
    if (err) {
      return cb(err);
    }

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

      dbug('"%s" delegates to "%s"', delegationChain[delegationChain.length - 2],
                   delegationChain[delegationChain.length - 1]);

      // check for max delegation length (max delegations of n, implies we can have a chain
      // length of n + 1.  IOW, a chain of length 10, has 9 authority delegations.
      if (delegationChain.length > (args.maxDelegations + 1)) {
        return cb("Too many hops while delegating authority: " + delegationChain.join(" > "));
      }

      // recurse
      return lookup(emitter, args, currentDomain, principalDomain, cb, delegationChain);
    }
    else if (supportDoc.type === 'supported')
    {
      var url_prefix = 'https://' + currentDomain;

      var details = {
        // For b/w compat export both a single "current key"
        // as well as a list of all acceptable keys.
        publicKey: supportDoc.publicKey,
        publicKeys: supportDoc.publicKeys,
        delegationChain: delegationChain,
        authoritativeDomain: delegationChain[delegationChain.length - 1],
        urls: {
        }
      };

      // The well-known parser has verified that urls are present.
      details.urls.auth = url_prefix + supportDoc.paths.authentication;
      details.urls.prov = url_prefix + supportDoc.paths.provisioning;

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

module.exports = function (browserid, args, cb) {
  lookup(browserid, args, args.domain, args.principalDomain, function(err, details) {
    // if there is an error, then let's try the fallback if configured
    if (err && args.fallback) {
      return lookup(browserid, args, args.fallback, args.principalDomain, cb, [ args.fallback ]);
    }
    cb(err, details);
  });
};
