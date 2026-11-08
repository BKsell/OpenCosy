'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'kem', prefix: 'KEM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateKemGuard: guard.evaluate,
  summarizeKemGuard: guard.summarize,
  describeKemGuard: guard.describe,
};
