'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tdigest', prefix: 'TDIGEST' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTdigestGuard: guard.evaluate,
  summarizeTdigestGuard: guard.summarize,
  describeTdigestGuard: guard.describe,
};
