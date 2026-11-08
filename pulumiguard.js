'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'pulumi', prefix: 'PULUMI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePulumiGuard: guard.evaluate,
  summarizePulumiGuard: guard.summarize,
  describePulumiGuard: guard.describe,
};
