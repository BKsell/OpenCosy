'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'slsa', prefix: 'SLSA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSlsaGuard: guard.evaluate,
  summarizeSlsaGuard: guard.summarize,
  describeSlsaGuard: guard.describe,
};
