'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'PERMISSIO', label: 'Permissions-Policy background-sync' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionbackgroundsyncGuard: guard.evaluate,
  describePermissionbackgroundsyncGuard: guard.describe,
};
