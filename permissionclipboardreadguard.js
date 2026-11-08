'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: '剪贴板权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionclipboardread: guard.evaluate,
  summarizePermissionclipboardread: guard.summarize,
  describePermissionclipboardread: guard.describe,
};
