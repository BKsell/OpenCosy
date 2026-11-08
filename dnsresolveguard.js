'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'dnsresolve', prefix: 'DNSRESOLV' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDnsresolveGuard: guard.evaluate,
  summarizeDnsresolveGuard: guard.summarize,
  describeDnsresolveGuard: guard.describe,
};
