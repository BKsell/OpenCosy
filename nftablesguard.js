'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'nftables', prefix: 'NFTABLES' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNftablesGuard: guard.evaluate,
  summarizeNftablesGuard: guard.summarize,
  describeNftablesGuard: guard.describe,
};
