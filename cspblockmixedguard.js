'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cspblockmixed', prefix: 'CSPBLOCKM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCspblockmixedGuard: guard.evaluate,
  summarizeCspblockmixedGuard: guard.summarize,
  describeCspblockmixedGuard: guard.describe,
};
