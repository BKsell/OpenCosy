'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'chrony', prefix: 'CHRONY' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateChronyGuard: guard.evaluate,
  summarizeChronyGuard: guard.summarize,
  describeChronyGuard: guard.describe,
};
