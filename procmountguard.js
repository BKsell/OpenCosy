'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'procmount', prefix: 'PROCMOUNT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateProcmountGuard: guard.evaluate,
  summarizeProcmountGuard: guard.summarize,
  describeProcmountGuard: guard.describe,
};
