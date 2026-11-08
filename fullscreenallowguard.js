'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'fullscreenallow', prefix: 'FULLSCREE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFullscreenallowGuard: guard.evaluate,
  summarizeFullscreenallowGuard: guard.summarize,
  describeFullscreenallowGuard: guard.describe,
};
