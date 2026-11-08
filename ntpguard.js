'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ntp', prefix: 'NTP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNtpGuard: guard.evaluate,
  summarizeNtpGuard: guard.summarize,
  describeNtpGuard: guard.describe,
};
