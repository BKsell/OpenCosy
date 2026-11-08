'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'lockdown', prefix: 'LOCKDOWN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateLockdownGuard: guard.evaluate,
  summarizeLockdownGuard: guard.summarize,
  describeLockdownGuard: guard.describe,
};
