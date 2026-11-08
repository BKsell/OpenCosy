'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'weeknum', prefix: 'WEEKNUM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWeeknumGuard: guard.evaluate,
  summarizeWeeknumGuard: guard.summarize,
  describeWeeknumGuard: guard.describe,
};
