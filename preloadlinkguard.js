'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'preloadlink', prefix: 'PRELOADLI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePreloadlinkGuard: guard.evaluate,
  summarizePreloadlinkGuard: guard.summarize,
  describePreloadlinkGuard: guard.describe,
};
