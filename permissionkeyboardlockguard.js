'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: '键盘锁定权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionkeyboardlock: guard.evaluate,
  summarizePermissionkeyboardlock: guard.summarize,
  describePermissionkeyboardlock: guard.describe,
};
