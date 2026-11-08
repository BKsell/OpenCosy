'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'meltdown', prefix: 'MELTDOWN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMeltdownGuard: guard.evaluate,
  summarizeMeltdownGuard: guard.summarize,
  describeMeltdownGuard: guard.describe,
};
