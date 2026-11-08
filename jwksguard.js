'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'jwks', prefix: 'JWKS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateJwksGuard: guard.evaluate,
  summarizeJwksGuard: guard.summarize,
  describeJwksGuard: guard.describe,
};
