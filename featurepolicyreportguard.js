'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'featurepolicyreport', prefix: 'FEATUREPO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFeaturepolicyreportGuard: guard.evaluate,
  summarizeFeaturepolicyreportGuard: guard.summarize,
  describeFeaturepolicyreportGuard: guard.describe,
};
