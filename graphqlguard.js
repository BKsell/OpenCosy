'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'graphql', prefix: 'GRAPHQL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateGraphqlGuard: guard.evaluate,
  summarizeGraphqlGuard: guard.summarize,
  describeGraphqlGuard: guard.describe,
};
