'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'stackpivot', prefix: 'STACKPIVO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateStackpivotGuard: guard.evaluate,
  summarizeStackpivotGuard: guard.summarize,
  describeStackpivotGuard: guard.describe,
};
