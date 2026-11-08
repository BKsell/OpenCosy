'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: '支付权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionpaymentrequire: guard.evaluate,
  summarizePermissionpaymentrequire: guard.summarize,
  describePermissionpaymentrequire: guard.describe,
};
