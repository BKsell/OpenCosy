'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'dns', prefix: 'DNS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDnsGuard: guard.evaluate,
  summarizeDnsGuard: guard.summarize,
  describeDnsGuard: guard.describe,
};
