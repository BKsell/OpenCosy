'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'hpkpreport', prefix: 'HPKPREPOR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHpkpreportGuard: guard.evaluate,
  summarizeHpkpreportGuard: guard.summarize,
  describeHpkpreportGuard: guard.describe,
};
