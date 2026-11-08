'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'epoch', prefix: 'EPOCH' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEpochGuard: guard.evaluate,
  summarizeEpochGuard: guard.summarize,
  describeEpochGuard: guard.describe,
};
