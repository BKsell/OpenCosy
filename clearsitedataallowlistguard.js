'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'CLEARSITE', label: 'Clear-Site-Data allowlist' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateClearsitedataallowlistGuard: guard.evaluate,
  describeClearsitedataallowlistGuard: guard.describe,
};
