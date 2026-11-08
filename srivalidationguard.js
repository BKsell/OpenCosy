'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'srivalidation', prefix: 'SRIVALIDA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSrivalidationGuard: guard.evaluate,
  summarizeSrivalidationGuard: guard.summarize,
  describeSrivalidationGuard: guard.describe,
};
