'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sandboxseccomp', prefix: 'SANDBOXSE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSandboxseccompGuard: guard.evaluate,
  summarizeSandboxseccompGuard: guard.summarize,
  describeSandboxseccompGuard: guard.describe,
};
