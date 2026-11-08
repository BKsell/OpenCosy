'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'skiplist', prefix: 'SKIPLIST' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSkiplistGuard: guard.evaluate,
  summarizeSkiplistGuard: guard.summarize,
  describeSkiplistGuard: guard.describe,
};
