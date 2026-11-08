'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'csv', prefix: 'CSV' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCsvGuard: guard.evaluate,
  summarizeCsvGuard: guard.summarize,
  describeCsvGuard: guard.describe,
};
