'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'bgp', prefix: 'BGP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBgpGuard: guard.evaluate,
  summarizeBgpGuard: guard.summarize,
  describeBgpGuard: guard.describe,
};
