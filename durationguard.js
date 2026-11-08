'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'duration', prefix: 'DURATION' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDurationGuard: guard.evaluate,
  summarizeDurationGuard: guard.summarize,
  describeDurationGuard: guard.describe,
};
