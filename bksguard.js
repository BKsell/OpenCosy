'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'bks', prefix: 'BKS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBksGuard: guard.evaluate,
  summarizeBksGuard: guard.summarize,
  describeBksGuard: guard.describe,
};
