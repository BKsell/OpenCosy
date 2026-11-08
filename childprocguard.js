'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'childproc', prefix: 'CHILDPROC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateChildprocGuard: guard.evaluate,
  summarizeChildprocGuard: guard.summarize,
  describeChildprocGuard: guard.describe,
};
