'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'brotli', prefix: 'BROTLI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBrotliGuard: guard.evaluate,
  summarizeBrotliGuard: guard.summarize,
  describeBrotliGuard: guard.describe,
};
