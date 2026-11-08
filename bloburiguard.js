'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'bloburi', prefix: 'BLOBURI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBloburiGuard: guard.evaluate,
  summarizeBloburiGuard: guard.summarize,
  describeBloburiGuard: guard.describe,
};
