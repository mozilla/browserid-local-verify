#!/usr/bin/env node

var
BrowserID = require('../'),
colors = require('colors');

colors.setTheme({
  input: 'grey',
  verbose: 'grey',
  prompt: 'grey',
  info: 'green',
  data: 'grey',
  help: 'cyan',
  warn: 'yellow',
  debug: 'blue',
  error: 'red'
});

var args = require('optimist')
.usage('Perform BrowserID lookup to determine the authority for a specific domain.\nUsage: $0')
.alias('h', 'help')
.describe('h', 'display this usage message')
.alias('f', 'fallback')
.describe('f', 'domain of fallback IdP (often - login.persona.org)')
.alias('p', 'principalDomain')
.describe('p', 'specify the prinicpal email domain')
.alias('v', 'verbose')
.boolean('v')
.describe('v', 'print annoyinglymuch info about the discovery process')
var argv = args.argv;

if (argv.h || argv._.length !== 1) {
  args.showHelp();
  process.exit(1);
}

var domain = argv._[0];
var principalDomain = argv.p || domain;

var browserid = new BrowserID({
  fallback: argv.fallback
});

if (argv.v) {
  browserid.on('debug', function(msg) {
    console.log('debug'.warn + ':', msg);
  });
  browserid.on('metric', function(msg, value) {
    console.log(msg.warn + ':', value);
  });
}

browserid.lookup(domain, principalDomain, function(err, details) {
  if (err) {
    console.log("no support:".error, err);
  } else {
    if (argv.v) console.log("\n");
    // convert publicKey to displayable object
    details.publicKey = details.publicKey.toSimpleObject();
    console.log(details.authoritativeDomain.info, "is authoritative for", '@' + principalDomain.info, "email addresses:", JSON.stringify(details, null, 2).data);
  }
});
