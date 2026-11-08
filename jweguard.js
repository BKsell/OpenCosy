'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'jwe', prefix: 'JWE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateJweGuard: guard.evaluate,
  summarizeJweGuard: guard.summarize,
  describeJweGuard: guard.describe,
};
