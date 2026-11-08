'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: '本地网络权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionlocalnetwork: guard.evaluate,
  summarizePermissionlocalnetwork: guard.summarize,
  describePermissionlocalnetwork: guard.describe,
};
