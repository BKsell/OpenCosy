'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'oidc', prefix: 'OIDC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOidcGuard: guard.evaluate,
  summarizeOidcGuard: guard.summarize,
  describeOidcGuard: guard.describe,
};
