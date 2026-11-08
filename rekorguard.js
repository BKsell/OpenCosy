'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'rekor', prefix: 'REKOR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRekorGuard: guard.evaluate,
  summarizeRekorGuard: guard.summarize,
  describeRekorGuard: guard.describe,
};
