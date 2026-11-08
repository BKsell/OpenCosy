'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'aslrload', prefix: 'ASLRLOAD' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAslrloadGuard: guard.evaluate,
  summarizeAslrloadGuard: guard.summarize,
  describeAslrloadGuard: guard.describe,
};
