'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'REPORTING', label: 'Reporting-Endpoints' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateReportingsendgroup: guard.evaluate,
  summarizeReportingsendgroup: guard.summarize,
  describeReportingsendgroup: guard.describe,
};
