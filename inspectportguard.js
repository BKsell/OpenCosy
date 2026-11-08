'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'inspectport', prefix: 'INSPECTPO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateInspectportGuard: guard.evaluate,
  summarizeInspectportGuard: guard.summarize,
  describeInspectportGuard: guard.describe,
};
