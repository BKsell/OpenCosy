'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'smuggle', prefix: 'SMUGGLE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSmuggleGuard: guard.evaluate,
  summarizeSmuggleGuard: guard.summarize,
  describeSmuggleGuard: guard.describe,
};
