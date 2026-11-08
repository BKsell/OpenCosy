'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'proxyresolve', prefix: 'PROXYRESO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateProxyresolveGuard: guard.evaluate,
  summarizeProxyresolveGuard: guard.summarize,
  describeProxyresolveGuard: guard.describe,
};
