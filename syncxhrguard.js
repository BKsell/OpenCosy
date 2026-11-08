'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'syncxhr', prefix: 'SYNCXHR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSyncxhrGuard: guard.evaluate,
  summarizeSyncxhrGuard: guard.summarize,
  describeSyncxhrGuard: guard.describe,
};
