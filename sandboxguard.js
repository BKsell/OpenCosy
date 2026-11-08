'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sandbox', prefix: 'SANDBOX' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSandboxGuard: guard.evaluate,
  summarizeSandboxGuard: guard.summarize,
  describeSandboxGuard: guard.describe,
};
