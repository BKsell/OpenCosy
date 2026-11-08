'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: '广告竞价权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionrunadauction: guard.evaluate,
  summarizePermissionrunadauction: guard.summarize,
  describePermissionrunadauction: guard.describe,
};
