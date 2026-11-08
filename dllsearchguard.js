'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'dllsearch', prefix: 'DLLSEARCH' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDllsearchGuard: guard.evaluate,
  summarizeDllsearchGuard: guard.summarize,
  describeDllsearchGuard: guard.describe,
};
