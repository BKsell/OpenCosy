'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sem', prefix: 'SEM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSemGuard: guard.evaluate,
  summarizeSemGuard: guard.summarize,
  describeSemGuard: guard.describe,
};
