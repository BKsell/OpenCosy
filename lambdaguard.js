'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'lambda', prefix: 'LAMBDA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateLambdaGuard: guard.evaluate,
  summarizeLambdaGuard: guard.summarize,
  describeLambdaGuard: guard.describe,
};
