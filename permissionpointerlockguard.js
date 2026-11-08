'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: '指针锁定权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionpointerlock: guard.evaluate,
  summarizePermissionpointerlock: guard.summarize,
  describePermissionpointerlock: guard.describe,
};
