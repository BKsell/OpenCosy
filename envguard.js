'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'env', prefix: 'ENV' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEnvGuard: guard.evaluate,
  summarizeEnvGuard: guard.summarize,
  describeEnvGuard: guard.describe,
};
