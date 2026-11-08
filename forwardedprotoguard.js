'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'forwardedproto', prefix: 'FORWARDED' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateForwardedprotoGuard: guard.evaluate,
  summarizeForwardedprotoGuard: guard.summarize,
  describeForwardedprotoGuard: guard.describe,
};
