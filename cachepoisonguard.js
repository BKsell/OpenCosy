'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cachepoison', prefix: 'CACHEPOIS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCachepoisonGuard: guard.evaluate,
  summarizeCachepoisonGuard: guard.summarize,
  describeCachepoisonGuard: guard.describe,
};
