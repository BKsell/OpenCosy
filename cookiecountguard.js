'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cookiecount', prefix: 'COOKIECOU' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCookiecountGuard: guard.evaluate,
  summarizeCookiecountGuard: guard.summarize,
  describeCookiecountGuard: guard.describe,
};
