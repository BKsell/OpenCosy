'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ueficapsule', prefix: 'UEFICAPSU' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateUeficapsuleGuard: guard.evaluate,
  summarizeUeficapsuleGuard: guard.summarize,
  describeUeficapsuleGuard: guard.describe,
};
