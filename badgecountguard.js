'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'badgecount', prefix: 'BADGECOUN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBadgecountGuard: guard.evaluate,
  summarizeBadgecountGuard: guard.summarize,
  describeBadgecountGuard: guard.describe,
};
