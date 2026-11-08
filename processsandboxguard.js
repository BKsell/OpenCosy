'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'processsandbox', prefix: 'PROCESSSA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateProcesssandboxGuard: guard.evaluate,
  summarizeProcesssandboxGuard: guard.summarize,
  describeProcesssandboxGuard: guard.describe,
};
