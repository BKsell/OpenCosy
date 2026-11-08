'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'subtitle', prefix: 'SUBTITLE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSubtitleGuard: guard.evaluate,
  summarizeSubtitleGuard: guard.summarize,
  describeSubtitleGuard: guard.describe,
};
