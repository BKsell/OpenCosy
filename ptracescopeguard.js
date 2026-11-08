'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ptracescope', prefix: 'PTRACESCO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePtracescopeGuard: guard.evaluate,
  summarizePtracescopeGuard: guard.summarize,
  describePtracescopeGuard: guard.describe,
};
