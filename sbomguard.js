'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sbom', prefix: 'SBOM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSbomGuard: guard.evaluate,
  summarizeSbomGuard: guard.summarize,
  describeSbomGuard: guard.describe,
};
