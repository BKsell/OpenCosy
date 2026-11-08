'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sanvalidation', prefix: 'SANVALIDA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSanvalidationGuard: guard.evaluate,
  summarizeSanvalidationGuard: guard.summarize,
  describeSanvalidationGuard: guard.describe,
};
