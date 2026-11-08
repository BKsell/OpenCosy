'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'prockcore', prefix: 'PROCKCORE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateProckcoreGuard: guard.evaluate,
  summarizeProckcoreGuard: guard.summarize,
  describeProckcoreGuard: guard.describe,
};
