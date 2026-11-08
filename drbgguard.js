'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'drbg', prefix: 'DRBG' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDrbgGuard: guard.evaluate,
  summarizeDrbgGuard: guard.summarize,
  describeDrbgGuard: guard.describe,
};
