'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ecdsa', prefix: 'ECDSA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEcdsaGuard: guard.evaluate,
  summarizeEcdsaGuard: guard.summarize,
  describeEcdsaGuard: guard.describe,
};
