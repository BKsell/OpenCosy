'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'COOKIEDOM', label: 'Cookie Domain scope' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCookiedomainscopeGuard: guard.evaluate,
  describeCookiedomainscopeGuard: guard.describe,
};
