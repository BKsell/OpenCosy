'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'permreport', prefix: 'PERMREPOR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermreportGuard: guard.evaluate,
  summarizePermreportGuard: guard.summarize,
  describePermreportGuard: guard.describe,
};
