'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'CSPMEDIAS', label: 'CSP media-src directive' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCspmediasrcGuard: guard.evaluate,
  describeCspmediasrcGuard: guard.describe,
};
