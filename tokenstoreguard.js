'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tokenstore', prefix: 'TOKENSTOR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTokenstoreGuard: guard.evaluate,
  summarizeTokenstoreGuard: guard.summarize,
  describeTokenstoreGuard: guard.describe,
};
