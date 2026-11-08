'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: '受控框架权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissioncontrolledframe: guard.evaluate,
  summarizePermissioncontrolledframe: guard.summarize,
  describePermissioncontrolledframe: guard.describe,
};
