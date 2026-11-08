'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'findinpage', prefix: 'FINDINPAG' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFindinpageGuard: guard.evaluate,
  summarizeFindinpageGuard: guard.summarize,
  describeFindinpageGuard: guard.describe,
};
