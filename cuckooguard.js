'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cuckoo', prefix: 'CUCKOO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCuckooGuard: guard.evaluate,
  summarizeCuckooGuard: guard.summarize,
  describeCuckooGuard: guard.describe,
};
