'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'PERMISSIO', label: 'Permissions-Policy ambient-light-sensor' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionambientlightsensorGuard: guard.evaluate,
  describePermissionambientlightsensorGuard: guard.describe,
};
