'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'bootparam', prefix: 'BOOTPARAM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBootparamGuard: guard.evaluate,
  summarizeBootparamGuard: guard.summarize,
  describeBootparamGuard: guard.describe,
};
