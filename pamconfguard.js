'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'pamconf', prefix: 'PAMCONF' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePamconfGuard: guard.evaluate,
  summarizePamconfGuard: guard.summarize,
  describePamconfGuard: guard.describe,
};
