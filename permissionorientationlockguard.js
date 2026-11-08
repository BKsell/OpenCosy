'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: '屏幕方向锁定权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionorientationlock: guard.evaluate,
  summarizePermissionorientationlock: guard.summarize,
  describePermissionorientationlock: guard.describe,
};
