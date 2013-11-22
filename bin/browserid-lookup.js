#!/usr/bin/env node

/* this should be invoked as follows
 *
 * browserid-lookup [args] <domain>
 */

var
BrowserID = require("..");

var args = require('optimist')
.usage('Determine whether a domain supports BrowserID.\nUsage: $0')
.alias('h', 'help')
.describe('h', 'display this usage message')
.alias('k', 'keylength')
var argv = args.argv;

if (argv.h) {
  args.showHelp();
  process.exit(1);
}

BrowserID.lookup(process.argv[(process.argv.length - 1)], null, function(err, details) {
  console.log(err, details);
});
