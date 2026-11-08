'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'rego', prefix: 'REGO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRegoGuard: guard.evaluate,
  summarizeRegoGuard: guard.summarize,
  describeRegoGuard: guard.describe,
};
