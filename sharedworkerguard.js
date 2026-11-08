'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sharedworker', prefix: 'SHAREDWOR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSharedworkerGuard: guard.evaluate,
  summarizeSharedworkerGuard: guard.summarize,
  describeSharedworkerGuard: guard.describe,
};
