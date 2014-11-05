/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* This file is an abstraction which can allocate delegation chains, that is
 * a group of IdP's which delegate in series.  Client code can then manipulate
 * individual elements in the chain independently.
 */

const
async = require('async'),
  IdP = require('./idp.js');

// a member function of the array returned from module.exports.  This allows stopping
// all members of a delegation chain simultaneously.
function stop(cb) {
  async.each(this, function(x, done) {
    x.stop(done);
  }, cb);
}

/* allocate a delegation chain of size [num].
 * returns via callback with a signature of (err, [array of idps]) */
module.exports = function(num, cb) {
  async.times(num, function(x, done) {
    var idp = new IdP({
      algorithm: 'DS',
      keysize: 128
    });
    idp.start(function(err) {
      done(err, idp);
    });
  }, function(err, results) {
    if (!err) {
      // now link up the chain.
      var domain = results[num-1].domain();
      for (var i = num - 2; i >= 0; i--) {
        results[i].delegation(domain);
        domain = results[i].domain();
      }
      // add a convenience function to stop all of the servers in the chain
      results.stop = stop;
    }
    cb(err, results);
  });
};
