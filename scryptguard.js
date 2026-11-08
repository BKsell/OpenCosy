'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'scrypt', prefix: 'SCRYPT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateScryptGuard: guard.evaluate,
  summarizeScryptGuard: guard.summarize,
  describeScryptGuard: guard.describe,
};
