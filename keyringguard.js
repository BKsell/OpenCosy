'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'keyring', prefix: 'KEYRING' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateKeyringGuard: guard.evaluate,
  summarizeKeyringGuard: guard.summarize,
  describeKeyringGuard: guard.describe,
};
