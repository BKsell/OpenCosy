'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'coredumpfilter', prefix: 'COREDUMPF' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCoredumpfilterGuard: guard.evaluate,
  summarizeCoredumpfilterGuard: guard.summarize,
  describeCoredumpfilterGuard: guard.describe,
};
