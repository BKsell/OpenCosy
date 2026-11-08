'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'dnssec', prefix: 'DNSSEC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDnssecGuard: guard.evaluate,
  summarizeDnssecGuard: guard.summarize,
  describeDnssecGuard: guard.describe,
};
