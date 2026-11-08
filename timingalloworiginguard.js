'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'timingalloworigin', prefix: 'TIMINGALL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTimingalloworiginGuard: guard.evaluate,
  summarizeTimingalloworiginGuard: guard.summarize,
  describeTimingalloworiginGuard: guard.describe,
};
