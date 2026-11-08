'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'masterkey', prefix: 'MASTERKEY' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMasterkeyGuard: guard.evaluate,
  summarizeMasterkeyGuard: guard.summarize,
  describeMasterkeyGuard: guard.describe,
};
