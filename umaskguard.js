'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'umask', prefix: 'UMASK' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateUmaskGuard: guard.evaluate,
  summarizeUmaskGuard: guard.summarize,
  describeUmaskGuard: guard.describe,
};
