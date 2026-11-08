'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tabdrag', prefix: 'TABDRAG' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTabdragGuard: guard.evaluate,
  summarizeTabdragGuard: guard.summarize,
  describeTabdragGuard: guard.describe,
};
