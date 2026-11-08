'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'hashpolicy', prefix: 'HASHPOLIC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHashpolicyGuard: guard.evaluate,
  summarizeHashpolicyGuard: guard.summarize,
  describeHashpolicyGuard: guard.describe,
};
