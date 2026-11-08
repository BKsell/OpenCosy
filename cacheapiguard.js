'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cacheapi', prefix: 'CACHEAPI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCacheapiGuard: guard.evaluate,
  summarizeCacheapiGuard: guard.summarize,
  describeCacheapiGuard: guard.describe,
};
