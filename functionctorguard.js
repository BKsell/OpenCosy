'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'functionctor', prefix: 'FUNCTIONC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFunctionctorGuard: guard.evaluate,
  summarizeFunctionctorGuard: guard.summarize,
  describeFunctionctorGuard: guard.describe,
};
