'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'historymenu', prefix: 'HISTORYME' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHistorymenuGuard: guard.evaluate,
  summarizeHistorymenuGuard: guard.summarize,
  describeHistorymenuGuard: guard.describe,
};
