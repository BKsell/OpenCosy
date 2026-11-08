'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'crashreport', prefix: 'CRASHREPO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCrashreportGuard: guard.evaluate,
  summarizeCrashreportGuard: guard.summarize,
  describeCrashreportGuard: guard.describe,
};
