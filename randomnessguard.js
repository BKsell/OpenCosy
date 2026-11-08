'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'randomness', prefix: 'RANDOMNES' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRandomnessGuard: guard.evaluate,
  summarizeRandomnessGuard: guard.summarize,
  describeRandomnessGuard: guard.describe,
};
