'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'seed', prefix: 'SEED' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSeedGuard: guard.evaluate,
  summarizeSeedGuard: guard.summarize,
  describeSeedGuard: guard.describe,
};
