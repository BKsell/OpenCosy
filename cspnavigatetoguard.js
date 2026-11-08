'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'CSPNAVIGA', label: 'CSP navigate-to directive' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCspnavigatetoGuard: guard.evaluate,
  describeCspnavigatetoGuard: guard.describe,
};
