'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tls', prefix: 'TLS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTlsGuard: guard.evaluate,
  summarizeTlsGuard: guard.summarize,
  describeTlsGuard: guard.describe,
};
