'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'avltree', prefix: 'AVLTREE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAvltreeGuard: guard.evaluate,
  summarizeAvltreeGuard: guard.summarize,
  describeAvltreeGuard: guard.describe,
};
