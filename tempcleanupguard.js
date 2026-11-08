'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tempcleanup', prefix: 'TEMPCLEAN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTempcleanupGuard: guard.evaluate,
  summarizeTempcleanupGuard: guard.summarize,
  describeTempcleanupGuard: guard.describe,
};
