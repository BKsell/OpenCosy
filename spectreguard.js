'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'spectre', prefix: 'SPECTRE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSpectreGuard: guard.evaluate,
  summarizeSpectreGuard: guard.summarize,
  describeSpectreGuard: guard.describe,
};
