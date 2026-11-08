'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sessioncleanup', prefix: 'SESSIONCL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSessioncleanupGuard: guard.evaluate,
  summarizeSessioncleanupGuard: guard.summarize,
  describeSessioncleanupGuard: guard.describe,
};
