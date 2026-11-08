'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'safemode', prefix: 'SAFEMODE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSafemodeGuard: guard.evaluate,
  summarizeSafemodeGuard: guard.summarize,
  describeSafemodeGuard: guard.describe,
};
