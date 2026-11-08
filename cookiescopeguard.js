'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cookiescope', prefix: 'COOKIESCO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCookiescopeGuard: guard.evaluate,
  summarizeCookiescopeGuard: guard.summarize,
  describeCookiescopeGuard: guard.describe,
};
