'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'seccomp', prefix: 'SECCOMP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSeccompGuard: guard.evaluate,
  summarizeSeccompGuard: guard.summarize,
  describeSeccompGuard: guard.describe,
};
