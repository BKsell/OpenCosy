'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ptp', prefix: 'PTP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePtpGuard: guard.evaluate,
  summarizePtpGuard: guard.summarize,
  describePtpGuard: guard.describe,
};
