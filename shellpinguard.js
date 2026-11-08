'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'shellpin', prefix: 'SHELLPIN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateShellpinGuard: guard.evaluate,
  summarizeShellpinGuard: guard.summarize,
  describeShellpinGuard: guard.describe,
};
