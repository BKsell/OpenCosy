'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'permissionsdefault', prefix: 'PERMISSIO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermissionsdefaultGuard: guard.evaluate,
  summarizePermissionsdefaultGuard: guard.summarize,
  describePermissionsdefaultGuard: guard.describe,
};
