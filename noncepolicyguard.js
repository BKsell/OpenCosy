'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'noncepolicy', prefix: 'NONCEPOLI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNoncepolicyGuard: guard.evaluate,
  summarizeNoncepolicyGuard: guard.summarize,
  describeNoncepolicyGuard: guard.describe,
};
