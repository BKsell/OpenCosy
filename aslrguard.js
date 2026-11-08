'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'aslr', prefix: 'ASLR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAslrGuard: guard.evaluate,
  summarizeAslrGuard: guard.summarize,
  describeAslrGuard: guard.describe,
};
