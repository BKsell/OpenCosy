'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'barrier', prefix: 'BARRIER' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBarrierGuard: guard.evaluate,
  summarizeBarrierGuard: guard.summarize,
  describeBarrierGuard: guard.describe,
};
