'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'forwardedheader', prefix: 'FORWARDED' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateForwardedheaderGuard: guard.evaluate,
  summarizeForwardedheaderGuard: guard.summarize,
  describeForwardedheaderGuard: guard.describe,
};
