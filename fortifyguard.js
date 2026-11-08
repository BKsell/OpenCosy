'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'fortify', prefix: 'FORTIFY' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFortifyGuard: guard.evaluate,
  summarizeFortifyGuard: guard.summarize,
  describeFortifyGuard: guard.describe,
};
