'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cookiesizelimit', prefix: 'COOKIESIZ' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCookiesizelimitGuard: guard.evaluate,
  summarizeCookiesizelimitGuard: guard.summarize,
  describeCookiesizelimitGuard: guard.describe,
};
