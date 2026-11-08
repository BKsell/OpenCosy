'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: '窗口管理权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionwindowmanagement: guard.evaluate,
  summarizePermissionwindowmanagement: guard.summarize,
  describePermissionwindowmanagement: guard.describe,
};
