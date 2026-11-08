'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cors', prefix: 'CORS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCorsGuard: guard.evaluate,
  summarizeCorsGuard: guard.summarize,
  describeCorsGuard: guard.describe,
};
