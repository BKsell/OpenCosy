'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'CONTENTSE', label: 'CSP 报告通道' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateContentsecuritypolicyreport: guard.evaluate,
  summarizeContentsecuritypolicyreport: guard.summarize,
  describeContentsecuritypolicyreport: guard.describe,
};
