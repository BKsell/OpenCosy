'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'syncmanager', prefix: 'SYNCMANAG' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSyncmanagerGuard: guard.evaluate,
  summarizeSyncmanagerGuard: guard.summarize,
  describeSyncmanagerGuard: guard.describe,
};
