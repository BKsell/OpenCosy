'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'frameancestor', prefix: 'FRAMEANCE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFrameancestorGuard: guard.evaluate,
  summarizeFrameancestorGuard: guard.summarize,
  describeFrameancestorGuard: guard.describe,
};
