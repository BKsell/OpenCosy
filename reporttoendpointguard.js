'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'reporttoendpoint', prefix: 'REPORTTOE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateReporttoendpointGuard: guard.evaluate,
  summarizeReporttoendpointGuard: guard.summarize,
  describeReporttoendpointGuard: guard.describe,
};
