'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'vrrp', prefix: 'VRRP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateVrrpGuard: guard.evaluate,
  summarizeVrrpGuard: guard.summarize,
  describeVrrpGuard: guard.describe,
};
