'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'trustedtype', prefix: 'TRUSTEDTY' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTrustedtypeGuard: guard.evaluate,
  summarizeTrustedtypeGuard: guard.summarize,
  describeTrustedtypeGuard: guard.describe,
};
