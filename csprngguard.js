'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'csprng', prefix: 'CSPRNG' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCsprngGuard: guard.evaluate,
  summarizeCsprngGuard: guard.summarize,
  describeCsprngGuard: guard.describe,
};
