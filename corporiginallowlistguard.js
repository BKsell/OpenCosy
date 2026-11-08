'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'CORPORIGI', label: 'Cross-Origin-Resource-Policy' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCorporiginallowlistGuard: guard.evaluate,
  describeCorporiginallowlistGuard: guard.describe,
};
