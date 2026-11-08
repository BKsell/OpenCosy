'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ratelimit', prefix: 'RATELIMIT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRatelimitGuard: guard.evaluate,
  summarizeRatelimitGuard: guard.summarize,
  describeRatelimitGuard: guard.describe,
};
