'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'heapdump', prefix: 'HEAPDUMP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHeapdumpGuard: guard.evaluate,
  summarizeHeapdumpGuard: guard.summarize,
  describeHeapdumpGuard: guard.describe,
};
