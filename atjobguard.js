'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'atjob', prefix: 'ATJOB' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAtjobGuard: guard.evaluate,
  summarizeAtjobGuard: guard.summarize,
  describeAtjobGuard: guard.describe,
};
