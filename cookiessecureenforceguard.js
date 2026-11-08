'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'COOKIESSE', label: 'Cookie Secure' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCookiessecureenforce: guard.evaluate,
  summarizeCookiessecureenforce: guard.summarize,
  describeCookiessecureenforce: guard.describe,
};
