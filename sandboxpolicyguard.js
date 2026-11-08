'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sandboxpolicy', prefix: 'SANDBOXPO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSandboxpolicyGuard: guard.evaluate,
  summarizeSandboxpolicyGuard: guard.summarize,
  describeSandboxpolicyGuard: guard.describe,
};
