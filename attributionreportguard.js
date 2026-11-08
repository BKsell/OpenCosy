'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'attributionreport', prefix: 'ATTRIBUTI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAttributionreportGuard: guard.evaluate,
  summarizeAttributionreportGuard: guard.summarize,
  describeAttributionreportGuard: guard.describe,
};
