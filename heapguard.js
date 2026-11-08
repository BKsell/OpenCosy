'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'heap', prefix: 'HEAP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHeapGuard: guard.evaluate,
  summarizeHeapGuard: guard.summarize,
  describeHeapGuard: guard.describe,
};
