'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'CSPFRAMES', label: 'CSP frame-src directive' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCspframesrcGuard: guard.evaluate,
  describeCspframesrcGuard: guard.describe,
};
