'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'CSPCONNEC', label: 'CSP connect-src directive' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCspconnectsrcGuard: guard.evaluate,
  describeCspconnectsrcGuard: guard.describe,
};
