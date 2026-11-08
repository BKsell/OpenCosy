'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'deque', prefix: 'DEQUE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDequeGuard: guard.evaluate,
  summarizeDequeGuard: guard.summarize,
  describeDequeGuard: guard.describe,
};
