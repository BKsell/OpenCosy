'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'CSPDEFAUL', label: 'CSP default-src directive' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCspdefaultsrcGuard: guard.evaluate,
  describeCspdefaultsrcGuard: guard.describe,
};
