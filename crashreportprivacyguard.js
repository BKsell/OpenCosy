'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'crashreportprivacy', prefix: 'CRASHREPO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCrashreportprivacyGuard: guard.evaluate,
  summarizeCrashreportprivacyGuard: guard.summarize,
  describeCrashreportprivacyGuard: guard.describe,
};
