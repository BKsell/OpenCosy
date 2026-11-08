'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'debugwire', prefix: 'DEBUGWIRE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDebugwireGuard: guard.evaluate,
  summarizeDebugwireGuard: guard.summarize,
  describeDebugwireGuard: guard.describe,
};
