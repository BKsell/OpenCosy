'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'PERMISSIO', label: 'Permissions-Policy fullscreen' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionfullscreenrequestGuard: guard.evaluate,
  describePermissionfullscreenrequestGuard: guard.describe,
};
