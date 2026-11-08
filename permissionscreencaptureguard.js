'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: '屏幕捕获权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionscreencapture: guard.evaluate,
  summarizePermissionscreencapture: guard.summarize,
  describePermissionscreencapture: guard.describe,
};
