'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: '麦克风权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionmicrophoneenforce: guard.evaluate,
  summarizePermissionmicrophoneenforce: guard.summarize,
  describePermissionmicrophoneenforce: guard.describe,
};
