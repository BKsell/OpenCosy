'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'random', prefix: 'RANDOM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRandomGuard: guard.evaluate,
  summarizeRandomGuard: guard.summarize,
  describeRandomGuard: guard.describe,
};
