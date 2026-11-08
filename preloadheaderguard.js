'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'preloadheader', prefix: 'PRELOADHE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePreloadheaderGuard: guard.evaluate,
  summarizePreloadheaderGuard: guard.summarize,
  describePreloadheaderGuard: guard.describe,
};
