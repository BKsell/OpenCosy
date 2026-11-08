'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'spinlock', prefix: 'SPINLOCK' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSpinlockGuard: guard.evaluate,
  summarizeSpinlockGuard: guard.summarize,
  describeSpinlockGuard: guard.describe,
};
