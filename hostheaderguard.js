'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'hostheader', prefix: 'HOSTHEADE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHostheaderGuard: guard.evaluate,
  summarizeHostheaderGuard: guard.summarize,
  describeHostheaderGuard: guard.describe,
};
