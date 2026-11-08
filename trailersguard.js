'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'trailers', prefix: 'TRAILERS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTrailersGuard: guard.evaluate,
  summarizeTrailersGuard: guard.summarize,
  describeTrailersGuard: guard.describe,
};
