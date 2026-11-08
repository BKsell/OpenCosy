'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'netfilter', prefix: 'NETFILTER' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNetfilterGuard: guard.evaluate,
  summarizeNetfilterGuard: guard.summarize,
  describeNetfilterGuard: guard.describe,
};
