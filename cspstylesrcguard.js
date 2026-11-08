'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'CSPSTYLES', label: 'CSP style-src directive' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCspstylesrcGuard: guard.evaluate,
  describeCspstylesrcGuard: guard.describe,
};
