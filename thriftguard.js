'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'thrift', prefix: 'THRIFT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateThriftGuard: guard.evaluate,
  summarizeThriftGuard: guard.summarize,
  describeThriftGuard: guard.describe,
};
