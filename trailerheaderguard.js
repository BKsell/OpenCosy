'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'trailerheader', prefix: 'TRAILERHE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTrailerheaderGuard: guard.evaluate,
  summarizeTrailerheaderGuard: guard.summarize,
  describeTrailerheaderGuard: guard.describe,
};
