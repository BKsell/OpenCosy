'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'referrerstrip', prefix: 'REFERRERS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateReferrerstripGuard: guard.evaluate,
  summarizeReferrerstripGuard: guard.summarize,
  describeReferrerstripGuard: guard.describe,
};
