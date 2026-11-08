'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sri', prefix: 'SRI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSriGuard: guard.evaluate,
  summarizeSriGuard: guard.summarize,
  describeSriGuard: guard.describe,
};
