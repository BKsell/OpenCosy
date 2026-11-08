'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'profinet', prefix: 'PROFINET' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateProfinetGuard: guard.evaluate,
  summarizeProfinetGuard: guard.summarize,
  describeProfinetGuard: guard.describe,
};
