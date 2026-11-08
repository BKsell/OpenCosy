'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'lru', prefix: 'LRU' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateLruGuard: guard.evaluate,
  summarizeLruGuard: guard.summarize,
  describeLruGuard: guard.describe,
};
