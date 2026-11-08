'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'bgphijack', prefix: 'BGPHIJACK' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBgphijackGuard: guard.evaluate,
  summarizeBgphijackGuard: guard.summarize,
  describeBgphijackGuard: guard.describe,
};
