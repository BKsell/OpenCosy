'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'httpdowngrade', prefix: 'HTTPDOWNG' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHttpdowngradeGuard: guard.evaluate,
  summarizeHttpdowngradeGuard: guard.summarize,
  describeHttpdowngradeGuard: guard.describe,
};
