'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cspreport', prefix: 'CSPREPORT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCspreportGuard: guard.evaluate,
  summarizeCspreportGuard: guard.summarize,
  describeCspreportGuard: guard.describe,
};
