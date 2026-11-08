'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'lfu', prefix: 'LFU' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateLfuGuard: guard.evaluate,
  summarizeLfuGuard: guard.summarize,
  describeLfuGuard: guard.describe,
};
