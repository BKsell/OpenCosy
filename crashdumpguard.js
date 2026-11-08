'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'crashdump', prefix: 'CRASHDUMP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCrashdumpGuard: guard.evaluate,
  summarizeCrashdumpGuard: guard.summarize,
  describeCrashdumpGuard: guard.describe,
};
