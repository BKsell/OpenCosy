'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'nonce', prefix: 'NONCE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNonceGuard: guard.evaluate,
  summarizeNonceGuard: guard.summarize,
  describeNonceGuard: guard.describe,
};
