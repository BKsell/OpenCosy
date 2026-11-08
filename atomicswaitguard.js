'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'atomicswait', prefix: 'ATOMICSWA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAtomicswaitGuard: guard.evaluate,
  summarizeAtomicswaitGuard: guard.summarize,
  describeAtomicswaitGuard: guard.describe,
};
