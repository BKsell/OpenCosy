'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'criticalchin', prefix: 'CRITICALC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCriticalchinGuard: guard.evaluate,
  summarizeCriticalchinGuard: guard.summarize,
  describeCriticalchinGuard: guard.describe,
};
