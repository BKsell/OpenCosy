'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'CSPMANIFE', label: 'CSP manifest-src directive' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCspmanifestsrcGuard: guard.evaluate,
  describeCspmanifestsrcGuard: guard.describe,
};
