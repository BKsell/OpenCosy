'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'thumbnail', prefix: 'THUMBNAIL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateThumbnailGuard: guard.evaluate,
  summarizeThumbnailGuard: guard.summarize,
  describeThumbnailGuard: guard.describe,
};
