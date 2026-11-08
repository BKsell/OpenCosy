'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'referrerheader', prefix: 'REFERRERH' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateReferrerheaderGuard: guard.evaluate,
  summarizeReferrerheaderGuard: guard.summarize,
  describeReferrerheaderGuard: guard.describe,
};
