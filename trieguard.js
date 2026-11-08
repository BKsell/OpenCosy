'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'trie', prefix: 'TRIE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTrieGuard: guard.evaluate,
  summarizeTrieGuard: guard.summarize,
  describeTrieGuard: guard.describe,
};
