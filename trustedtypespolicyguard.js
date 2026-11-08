'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'trustedtypespolicy', prefix: 'TRUSTEDTY' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTrustedtypespolicyGuard: guard.evaluate,
  summarizeTrustedtypespolicyGuard: guard.summarize,
  describeTrustedtypespolicyGuard: guard.describe,
};
