'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sgx', prefix: 'SGX' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSgxGuard: guard.evaluate,
  summarizeSgxGuard: guard.summarize,
  describeSgxGuard: guard.describe,
};
