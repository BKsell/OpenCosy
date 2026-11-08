'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cookiemaxage', prefix: 'COOKIEMAX' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCookiemaxageGuard: guard.evaluate,
  summarizeCookiemaxageGuard: guard.summarize,
  describeCookiemaxageGuard: guard.describe,
};
