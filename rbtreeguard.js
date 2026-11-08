'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'rbtree', prefix: 'RBTREE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRbtreeGuard: guard.evaluate,
  summarizeRbtreeGuard: guard.summarize,
  describeRbtreeGuard: guard.describe,
};
