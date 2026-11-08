'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'COOPSAMEO', label: 'Cross-Origin-Opener-Policy same-origin-allow-popups' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCoopsameoriginallowpopupsGuard: guard.evaluate,
  describeCoopsameoriginallowpopupsGuard: guard.describe,
};
