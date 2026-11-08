'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'dnsprefetch', prefix: 'DNSPREFET' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDnsprefetchGuard: guard.evaluate,
  summarizeDnsprefetchGuard: guard.summarize,
  describeDnsprefetchGuard: guard.describe,
};
