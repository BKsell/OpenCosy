'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'dynamicimport', prefix: 'DYNAMICIM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDynamicimportGuard: guard.evaluate,
  summarizeDynamicimportGuard: guard.summarize,
  describeDynamicimportGuard: guard.describe,
};
