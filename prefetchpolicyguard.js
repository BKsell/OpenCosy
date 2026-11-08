'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'prefetchpolicy', prefix: 'PREFETCHP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePrefetchpolicyGuard: guard.evaluate,
  summarizePrefetchpolicyGuard: guard.summarize,
  describePrefetchpolicyGuard: guard.describe,
};
