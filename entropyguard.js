'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'entropy', prefix: 'ENTROPY' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEntropyGuard: guard.evaluate,
  summarizeEntropyGuard: guard.summarize,
  describeEntropyGuard: guard.describe,
};
