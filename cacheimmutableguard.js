'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cacheimmutable', prefix: 'CACHEIMMU' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCacheimmutableGuard: guard.evaluate,
  summarizeCacheimmutableGuard: guard.summarize,
  describeCacheimmutableGuard: guard.describe,
};
