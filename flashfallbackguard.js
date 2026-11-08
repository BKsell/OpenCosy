'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'flashfallback', prefix: 'FLASHFALL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFlashfallbackGuard: guard.evaluate,
  summarizeFlashfallbackGuard: guard.summarize,
  describeFlashfallbackGuard: guard.describe,
};
