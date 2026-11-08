'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ttl', prefix: 'TTL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTtlGuard: guard.evaluate,
  summarizeTtlGuard: guard.summarize,
  describeTtlGuard: guard.describe,
};
