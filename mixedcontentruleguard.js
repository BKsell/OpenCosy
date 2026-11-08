'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'mixedcontentrule', prefix: 'MIXEDCONT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMixedcontentruleGuard: guard.evaluate,
  summarizeMixedcontentruleGuard: guard.summarize,
  describeMixedcontentruleGuard: guard.describe,
};
