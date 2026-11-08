'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'COOKIEHTT', label: 'Cookie HttpOnly' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCookiehttponlyrequire: guard.evaluate,
  summarizeCookiehttponlyrequire: guard.summarize,
  describeCookiehttponlyrequire: guard.describe,
};
