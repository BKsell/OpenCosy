'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'mount', prefix: 'MOUNT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMountGuard: guard.evaluate,
  summarizeMountGuard: guard.summarize,
  describeMountGuard: guard.describe,
};
