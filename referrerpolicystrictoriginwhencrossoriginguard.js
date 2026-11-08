'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'REFERRERP', label: 'Referrer-Policy strict-origin-when-cross-origin' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateReferrerpolicystrictoriginwhencrossoriginGuard: guard.evaluate,
  describeReferrerpolicystrictoriginwhencrossoriginGuard: guard.describe,
};
