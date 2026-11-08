'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'trailer', prefix: 'TRAILER' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTrailerGuard: guard.evaluate,
  summarizeTrailerGuard: guard.summarize,
  describeTrailerGuard: guard.describe,
};
