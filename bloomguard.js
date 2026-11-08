'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'bloom', prefix: 'BLOOM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBloomGuard: guard.evaluate,
  summarizeBloomGuard: guard.summarize,
  describeBloomGuard: guard.describe,
};
