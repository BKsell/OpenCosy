'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ipsec', prefix: 'IPSEC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateIpsecGuard: guard.evaluate,
  summarizeIpsecGuard: guard.summarize,
  describeIpsecGuard: guard.describe,
};
