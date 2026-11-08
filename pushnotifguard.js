'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'pushnotif', prefix: 'PUSHNOTIF' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePushnotifGuard: guard.evaluate,
  summarizePushnotifGuard: guard.summarize,
  describePushnotifGuard: guard.describe,
};
