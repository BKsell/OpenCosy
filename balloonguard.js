'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'balloon', prefix: 'BALLOON' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBalloonGuard: guard.evaluate,
  summarizeBalloonGuard: guard.summarize,
  describeBalloonGuard: guard.describe,
};
