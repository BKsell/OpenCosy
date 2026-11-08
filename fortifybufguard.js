'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'fortifybuf', prefix: 'FORTIFYBU' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFortifybufGuard: guard.evaluate,
  summarizeFortifybufGuard: guard.summarize,
  describeFortifybufGuard: guard.describe,
};
