'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'spf', prefix: 'SPF' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSpfGuard: guard.evaluate,
  summarizeSpfGuard: guard.summarize,
  describeSpfGuard: guard.describe,
};
