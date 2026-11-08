'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'CSPCHILDS', label: 'CSP child-src directive' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCspchildsrcGuard: guard.evaluate,
  describeCspchildsrcGuard: guard.describe,
};
