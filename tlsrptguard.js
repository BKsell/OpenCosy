'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tlsrpt', prefix: 'TLSRPT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTlsrptGuard: guard.evaluate,
  summarizeTlsrptGuard: guard.summarize,
  describeTlsrptGuard: guard.describe,
};
