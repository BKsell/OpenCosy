'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cosign', prefix: 'COSIGN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCosignGuard: guard.evaluate,
  summarizeCosignGuard: guard.summarize,
  describeCosignGuard: guard.describe,
};
