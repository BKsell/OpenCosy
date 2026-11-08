'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'permpolicy', prefix: 'PERMPOLIC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePermpolicyGuard: guard.evaluate,
  summarizePermpolicyGuard: guard.summarize,
  describePermpolicyGuard: guard.describe,
};
