'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'visibility', prefix: 'VISIBILIT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateVisibilityGuard: guard.evaluate,
  summarizeVisibilityGuard: guard.summarize,
  describeVisibilityGuard: guard.describe,
};
