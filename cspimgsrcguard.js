'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'CSPIMGSRC', label: 'CSP img-src directive' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCspimgsrcGuard: guard.evaluate,
  describeCspimgsrcGuard: guard.describe,
};
