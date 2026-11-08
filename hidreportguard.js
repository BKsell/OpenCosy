'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'hidreport', prefix: 'HIDREPORT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHidreportGuard: guard.evaluate,
  summarizeHidreportGuard: guard.summarize,
  describeHidreportGuard: guard.describe,
};
