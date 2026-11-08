'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PERMISSIO', label: '摄像头权限' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissioncameraenforce: guard.evaluate,
  summarizePermissioncameraenforce: guard.summarize,
  describePermissioncameraenforce: guard.describe,
};
