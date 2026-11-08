'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'keychain', prefix: 'KEYCHAIN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateKeychainGuard: guard.evaluate,
  summarizeKeychainGuard: guard.summarize,
  describeKeychainGuard: guard.describe,
};
