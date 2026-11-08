'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'gzip', prefix: 'GZIP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateGzipGuard: guard.evaluate,
  summarizeGzipGuard: guard.summarize,
  describeGzipGuard: guard.describe,
};
