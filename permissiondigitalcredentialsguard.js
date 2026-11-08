'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: '数字凭证权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissiondigitalcredentials: guard.evaluate,
  summarizePermissiondigitalcredentials: guard.summarize,
  describePermissiondigitalcredentials: guard.describe,
};
