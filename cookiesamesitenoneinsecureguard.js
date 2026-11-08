'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'COOKIESAM', label: 'Cookie SameSite=None secure pairing' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCookiesamesitenoneinsecureGuard: guard.evaluate,
  describeCookiesamesitenoneinsecureGuard: guard.describe,
};
