'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'prng', prefix: 'PRNG' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePrngGuard: guard.evaluate,
  summarizePrngGuard: guard.summarize,
  describePrngGuard: guard.describe,
};
