'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'allowlist', prefix: 'ALLOWLIST' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAllowlistGuard: guard.evaluate,
  summarizeAllowlistGuard: guard.summarize,
  describeAllowlistGuard: guard.describe,
};
