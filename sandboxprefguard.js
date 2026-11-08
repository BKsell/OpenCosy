'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sandboxpref', prefix: 'SANDBOXPR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSandboxprefGuard: guard.evaluate,
  summarizeSandboxprefGuard: guard.summarize,
  describeSandboxprefGuard: guard.describe,
};
