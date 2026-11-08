'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'rangeheader', prefix: 'RANGEHEAD' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRangeheaderGuard: guard.evaluate,
  summarizeRangeheaderGuard: guard.summarize,
  describeRangeheaderGuard: guard.describe,
};
