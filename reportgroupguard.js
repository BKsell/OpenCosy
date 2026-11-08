'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'reportgroup', prefix: 'REPORTGRO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateReportgroupGuard: guard.evaluate,
  summarizeReportgroupGuard: guard.summarize,
  describeReportgroupGuard: guard.describe,
};
