'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'COOKIEMAX', label: 'Cookie Max-Age bound' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCookiemaxageboundGuard: guard.evaluate,
  describeCookiemaxageboundGuard: guard.describe,
};
