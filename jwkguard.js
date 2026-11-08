'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'jwk', prefix: 'JWK' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateJwkGuard: guard.evaluate,
  summarizeJwkGuard: guard.summarize,
  describeJwkGuard: guard.describe,
};
