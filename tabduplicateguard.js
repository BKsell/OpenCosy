'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tabduplicate', prefix: 'TABDUPLIC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTabduplicateGuard: guard.evaluate,
  summarizeTabduplicateGuard: guard.summarize,
  describeTabduplicateGuard: guard.describe,
};
