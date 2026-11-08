'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'stackcanary', prefix: 'STACKCANA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateStackcanaryGuard: guard.evaluate,
  summarizeStackcanaryGuard: guard.summarize,
  describeStackcanaryGuard: guard.describe,
};
