'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'PERMISSIO', label: 'Permissions-Policy magnetometer' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionmagnetometerGuard: guard.evaluate,
  describePermissionmagnetometerGuard: guard.describe,
};
