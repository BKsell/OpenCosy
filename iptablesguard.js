'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'iptables', prefix: 'IPTABLES' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateIptablesGuard: guard.evaluate,
  summarizeIptablesGuard: guard.summarize,
  describeIptablesGuard: guard.describe,
};
