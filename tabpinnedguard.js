'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tabpinned', prefix: 'TABPINNED' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTabpinnedGuard: guard.evaluate,
  summarizeTabpinnedGuard: guard.summarize,
  describeTabpinnedGuard: guard.describe,
};
