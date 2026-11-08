'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'httpcachedirective', prefix: 'HTTPCACHE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHttpcachedirectiveGuard: guard.evaluate,
  summarizeHttpcachedirectiveGuard: guard.summarize,
  describeHttpcachedirectiveGuard: guard.describe,
};
