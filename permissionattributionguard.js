'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: '归因报告权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionattribution: guard.evaluate,
  summarizePermissionattribution: guard.summarize,
  describePermissionattribution: guard.describe,
};
