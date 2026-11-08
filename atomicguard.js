'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'atomic', prefix: 'ATOMIC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAtomicGuard: guard.evaluate,
  summarizeAtomicGuard: guard.summarize,
  describeAtomicGuard: guard.describe,
};
