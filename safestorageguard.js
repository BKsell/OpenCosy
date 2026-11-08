'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'safestorage', prefix: 'SAFESTORA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSafestorageGuard: guard.evaluate,
  summarizeSafestorageGuard: guard.summarize,
  describeSafestorageGuard: guard.describe,
};
