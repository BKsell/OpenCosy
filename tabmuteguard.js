'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tabmute', prefix: 'TABMUTE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTabmuteGuard: guard.evaluate,
  summarizeTabmuteGuard: guard.summarize,
  describeTabmuteGuard: guard.describe,
};
