'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'legacyfeaturepolicy', prefix: 'LEGACYFEA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateLegacyfeaturepolicyGuard: guard.evaluate,
  summarizeLegacyfeaturepolicyGuard: guard.summarize,
  describeLegacyfeaturepolicyGuard: guard.describe,
};
