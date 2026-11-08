'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sql', prefix: 'SQL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSqlGuard: guard.evaluate,
  summarizeSqlGuard: guard.summarize,
  describeSqlGuard: guard.describe,
};
