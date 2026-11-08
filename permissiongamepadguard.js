'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: '游戏手柄权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissiongamepad: guard.evaluate,
  summarizePermissiongamepad: guard.summarize,
  describePermissiongamepad: guard.describe,
};
