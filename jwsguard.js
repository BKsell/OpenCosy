'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'jws', prefix: 'JWS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateJwsGuard: guard.evaluate,
  summarizeJwsGuard: guard.summarize,
  describeJwsGuard: guard.describe,
};
