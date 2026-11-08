'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'dot', prefix: 'DOT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDotGuard: guard.evaluate,
  summarizeDotGuard: guard.summarize,
  describeDotGuard: guard.describe,
};
