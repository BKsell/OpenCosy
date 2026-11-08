'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'workletpolicy', prefix: 'WORKLETPO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWorkletpolicyGuard: guard.evaluate,
  summarizeWorkletpolicyGuard: guard.summarize,
  describeWorkletpolicyGuard: guard.describe,
};
