'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'wildcard', prefix: 'WILDCARD' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWildcardGuard: guard.evaluate,
  summarizeWildcardGuard: guard.summarize,
  describeWildcardGuard: guard.describe,
};
