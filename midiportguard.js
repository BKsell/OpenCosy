'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'midiport', prefix: 'MIDIPORT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMidiportGuard: guard.evaluate,
  summarizeMidiportGuard: guard.summarize,
  describeMidiportGuard: guard.describe,
};
