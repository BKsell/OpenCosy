'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sysrq', prefix: 'SYSRQ' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSysrqGuard: guard.evaluate,
  summarizeSysrqGuard: guard.summarize,
  describeSysrqGuard: guard.describe,
};
