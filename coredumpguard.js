'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'coredump', prefix: 'COREDUMP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCoredumpGuard: guard.evaluate,
  summarizeCoredumpGuard: guard.summarize,
  describeCoredumpGuard: guard.describe,
};
