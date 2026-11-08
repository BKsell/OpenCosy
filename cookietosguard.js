'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cookietos', prefix: 'COOKIETOS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCookietosGuard: guard.evaluate,
  summarizeCookietosGuard: guard.summarize,
  describeCookietosGuard: guard.describe,
};
