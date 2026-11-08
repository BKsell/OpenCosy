'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tmpscope', prefix: 'TMPSCOPE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTmpscopeGuard: guard.evaluate,
  summarizeTmpscopeGuard: guard.summarize,
  describeTmpscopeGuard: guard.describe,
};
