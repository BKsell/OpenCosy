'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'keystore', prefix: 'KEYSTORE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateKeystoreGuard: guard.evaluate,
  summarizeKeystoreGuard: guard.summarize,
  describeKeystoreGuard: guard.describe,
};
