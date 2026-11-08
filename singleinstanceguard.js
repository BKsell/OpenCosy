'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'singleinstance', prefix: 'SINGLEINS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSingleinstanceGuard: guard.evaluate,
  summarizeSingleinstanceGuard: guard.summarize,
  describeSingleinstanceGuard: guard.describe,
};
