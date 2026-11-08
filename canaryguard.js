'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'canary', prefix: 'CANARY' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCanaryGuard: guard.evaluate,
  summarizeCanaryGuard: guard.summarize,
  describeCanaryGuard: guard.describe,
};
