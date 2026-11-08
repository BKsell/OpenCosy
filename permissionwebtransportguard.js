'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: 'WebTransport 权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionwebtransport: guard.evaluate,
  summarizePermissionwebtransport: guard.summarize,
  describePermissionwebtransport: guard.describe,
};
