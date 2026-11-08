'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'CSPREQUIR', label: 'CSP require-trusted-types-for directive' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCsprequiretrustedtypesGuard: guard.evaluate,
  describeCsprequiretrustedtypesGuard: guard.describe,
};
