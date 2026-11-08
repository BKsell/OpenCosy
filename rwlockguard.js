'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'rwlock', prefix: 'RWLOCK' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRwlockGuard: guard.evaluate,
  summarizeRwlockGuard: guard.summarize,
  describeRwlockGuard: guard.describe,
};
