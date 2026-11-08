'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'snmptrap', prefix: 'SNMPTRAP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSnmptrapGuard: guard.evaluate,
  summarizeSnmptrapGuard: guard.summarize,
  describeSnmptrapGuard: guard.describe,
};
