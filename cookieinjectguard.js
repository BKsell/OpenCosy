'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cookieinject', prefix: 'COOKIEINJ' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCookieinjectGuard: guard.evaluate,
  summarizeCookieinjectGuard: guard.summarize,
  describeCookieinjectGuard: guard.describe,
};
