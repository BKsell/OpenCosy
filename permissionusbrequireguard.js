'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: 'USB 权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionusbrequire: guard.evaluate,
  summarizePermissionusbrequire: guard.summarize,
  describePermissionusbrequire: guard.describe,
};
