'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'heapspray', prefix: 'HEAPSPRAY' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHeapsprayGuard: guard.evaluate,
  summarizeHeapsprayGuard: guard.summarize,
  describeHeapsprayGuard: guard.describe,
};
