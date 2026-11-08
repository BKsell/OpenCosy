'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'SRICROSSO', label: 'Subresource Integrity cross-origin' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSricrossoriginrequireGuard: guard.evaluate,
  describeSricrossoriginrequireGuard: guard.describe,
};
