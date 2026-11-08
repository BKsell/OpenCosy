'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'elfinterp', prefix: 'ELFINTERP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateElfinterpGuard: guard.evaluate,
  summarizeElfinterpGuard: guard.summarize,
  describeElfinterpGuard: guard.describe,
};
