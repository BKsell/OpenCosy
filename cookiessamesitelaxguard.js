'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'COOKIESSA', label: 'Cookie SameSite' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCookiessamesitelax: guard.evaluate,
  summarizeCookiessamesitelax: guard.summarize,
  describeCookiessamesitelax: guard.describe,
};
