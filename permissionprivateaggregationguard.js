'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: '私密聚合权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionprivateaggregation: guard.evaluate,
  summarizePermissionprivateaggregation: guard.summarize,
  describePermissionprivateaggregation: guard.describe,
};
