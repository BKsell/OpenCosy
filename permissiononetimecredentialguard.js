'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: '一次性凭证权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissiononetimecredential: guard.evaluate,
  summarizePermissiononetimecredential: guard.summarize,
  describePermissiononetimecredential: guard.describe,
};
