'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'referrer', prefix: 'REFERRER' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateReferrerGuard: guard.evaluate,
  summarizeReferrerGuard: guard.summarize,
  describeReferrerGuard: guard.describe,
};
