'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'REFERRERP', label: 'Referrer-Policy no-referrer' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateReferrerpolicynoreferrerGuard: guard.evaluate,
  describeReferrerpolicynoreferrerGuard: guard.describe,
};
