'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: '存储访问权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionstorageaccess: guard.evaluate,
  summarizePermissionstorageaccess: guard.summarize,
  describePermissionstorageaccess: guard.describe,
};
