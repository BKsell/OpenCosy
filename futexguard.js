'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'futex', prefix: 'FUTEX' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFutexGuard: guard.evaluate,
  summarizeFutexGuard: guard.summarize,
  describeFutexGuard: guard.describe,
};
