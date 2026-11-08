'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: '共享存储权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionsharedstorage: guard.evaluate,
  summarizePermissionsharedstorage: guard.summarize,
  describePermissionsharedstorage: guard.describe,
};
