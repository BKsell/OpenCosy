'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cookiebomb', prefix: 'COOKIEBOM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCookiebombGuard: guard.evaluate,
  summarizeCookiebombGuard: guard.summarize,
  describeCookiebombGuard: guard.describe,
};
