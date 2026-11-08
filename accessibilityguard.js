'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'accessibility', prefix: 'ACCESSIBI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAccessibilityGuard: guard.evaluate,
  summarizeAccessibilityGuard: guard.summarize,
  describeAccessibilityGuard: guard.describe,
};
