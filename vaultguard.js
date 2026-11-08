'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'vault', prefix: 'VAULT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateVaultGuard: guard.evaluate,
  summarizeVaultGuard: guard.summarize,
  describeVaultGuard: guard.describe,
};
