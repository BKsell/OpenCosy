'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'vary', prefix: 'VARY' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateVaryGuard: guard.evaluate,
  summarizeVaryGuard: guard.summarize,
  describeVaryGuard: guard.describe,
};
