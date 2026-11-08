'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'PERMISSIO', label: 'Permissions-Policy screen-wake-lock' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionscreenwakelockGuard: guard.evaluate,
  describePermissionscreenwakelockGuard: guard.describe,
};
