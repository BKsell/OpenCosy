'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'rtfobj', prefix: 'RTFOBJ' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRtfobjGuard: guard.evaluate,
  summarizeRtfobjGuard: guard.summarize,
  describeRtfobjGuard: guard.describe,
};
