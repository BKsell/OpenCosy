'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'oidcjwt', prefix: 'OIDCJWT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOidcjwtGuard: guard.evaluate,
  summarizeOidcjwtGuard: guard.summarize,
  describeOidcjwtGuard: guard.describe,
};
