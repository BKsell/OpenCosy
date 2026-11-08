'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'pdf', prefix: 'PDF' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePdfGuard: guard.evaluate,
  summarizePdfGuard: guard.summarize,
  describePdfGuard: guard.describe,
};
