'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sigstore', prefix: 'SIGSTORE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSigstoreGuard: guard.evaluate,
  summarizeSigstoreGuard: guard.summarize,
  describeSigstoreGuard: guard.describe,
};
