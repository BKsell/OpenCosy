'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cspmanifest', prefix: 'CSPMANIFE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCspmanifestGuard: guard.evaluate,
  summarizeCspmanifestGuard: guard.summarize,
  describeCspmanifestGuard: guard.describe,
};
