'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'bson', prefix: 'BSON' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBsonGuard: guard.evaluate,
  summarizeBsonGuard: guard.summarize,
  describeBsonGuard: guard.describe,
};
