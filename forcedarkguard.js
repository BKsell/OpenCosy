'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'forcedark', prefix: 'FORCEDARK' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateForcedarkGuard: guard.evaluate,
  summarizeForcedarkGuard: guard.summarize,
  describeForcedarkGuard: guard.describe,
};
