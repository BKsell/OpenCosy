'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'savepath', prefix: 'SAVEPATH' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSavepathGuard: guard.evaluate,
  summarizeSavepathGuard: guard.summarize,
  describeSavepathGuard: guard.describe,
};
