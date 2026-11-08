'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'fsync', prefix: 'FSYNC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFsyncGuard: guard.evaluate,
  summarizeFsyncGuard: guard.summarize,
  describeFsyncGuard: guard.describe,
};
