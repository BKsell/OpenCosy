'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'bimi', prefix: 'BIMI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBimiGuard: guard.evaluate,
  summarizeBimiGuard: guard.summarize,
  describeBimiGuard: guard.describe,
};
