'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'splay', prefix: 'SPLAY' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSplayGuard: guard.evaluate,
  summarizeSplayGuard: guard.summarize,
  describeSplayGuard: guard.describe,
};
