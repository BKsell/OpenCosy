'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'samesite', prefix: 'SAMESITE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSamesiteGuard: guard.evaluate,
  summarizeSamesiteGuard: guard.summarize,
  describeSamesiteGuard: guard.describe,
};
