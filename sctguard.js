'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'sct', prefix: 'SCT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSctGuard: guard.evaluate,
  summarizeSctGuard: guard.summarize,
  describeSctGuard: guard.describe,
};
