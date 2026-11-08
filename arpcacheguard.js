'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'arpcache', prefix: 'ARPCACHE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateArpcacheGuard: guard.evaluate,
  summarizeArpcacheGuard: guard.summarize,
  describeArpcacheGuard: guard.describe,
};
