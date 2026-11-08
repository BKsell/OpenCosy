'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'execpolicy', prefix: 'EXECPOLIC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateExecpolicyGuard: guard.evaluate,
  summarizeExecpolicyGuard: guard.summarize,
  describeExecpolicyGuard: guard.describe,
};
