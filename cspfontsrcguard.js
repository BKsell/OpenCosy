'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'CSPFONTSR', label: 'CSP font-src directive' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCspfontsrcGuard: guard.evaluate,
  describeCspfontsrcGuard: guard.describe,
};
