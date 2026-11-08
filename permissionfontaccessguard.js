'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'PERMISSIO', label: 'Permissions-Policy local-fonts' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionfontaccessGuard: guard.evaluate,
  describePermissionfontaccessGuard: guard.describe,
};
