'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'indexeddb', prefix: 'INDEXEDDB' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateIndexeddbGuard: guard.evaluate,
  summarizeIndexeddbGuard: guard.summarize,
  describeIndexeddbGuard: guard.describe,
};
