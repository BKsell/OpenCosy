'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'finalization', prefix: 'FINALIZAT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFinalizationGuard: guard.evaluate,
  summarizeFinalizationGuard: guard.summarize,
  describeFinalizationGuard: guard.describe,
};
