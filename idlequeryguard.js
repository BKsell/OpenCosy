'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'idlequery', prefix: 'IDLEQUERY' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateIdlequeryGuard: guard.evaluate,
  summarizeIdlequeryGuard: guard.summarize,
  describeIdlequeryGuard: guard.describe,
};
