'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sysctl', prefix: 'SYSCTL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSysctlGuard: guard.evaluate,
  summarizeSysctlGuard: guard.summarize,
  describeSysctlGuard: guard.describe,
};
