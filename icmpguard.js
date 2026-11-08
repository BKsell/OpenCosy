'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'icmp', prefix: 'ICMP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateIcmpGuard: guard.evaluate,
  summarizeIcmpGuard: guard.summarize,
  describeIcmpGuard: guard.describe,
};
