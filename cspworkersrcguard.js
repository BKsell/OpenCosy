'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'CSPWORKER', label: 'CSP worker-src directive' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCspworkersrcGuard: guard.evaluate,
  describeCspworkersrcGuard: guard.describe,
};
