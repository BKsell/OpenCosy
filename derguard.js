'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'der', prefix: 'DER' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDerGuard: guard.evaluate,
  summarizeDerGuard: guard.summarize,
  describeDerGuard: guard.describe,
};
