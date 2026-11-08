'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'badgeapi', prefix: 'BADGEAPI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBadgeapiGuard: guard.evaluate,
  summarizeBadgeapiGuard: guard.summarize,
  describeBadgeapiGuard: guard.describe,
};
