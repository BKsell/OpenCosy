'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'CORSORIGI', label: 'CORS Origin allowlist' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCorsoriginallowlistGuard: guard.evaluate,
  describeCorsoriginallowlistGuard: guard.describe,
};
