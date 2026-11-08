'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'mimetype', prefix: 'MIMETYPE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMimetypeGuard: guard.evaluate,
  summarizeMimetypeGuard: guard.summarize,
  describeMimetypeGuard: guard.describe,
};
