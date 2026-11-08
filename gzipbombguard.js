'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'gzipbomb', prefix: 'GZIPBOMB' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateGzipbombGuard: guard.evaluate,
  summarizeGzipbombGuard: guard.summarize,
  describeGzipbombGuard: guard.describe,
};
