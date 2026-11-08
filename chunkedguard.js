'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'chunked', prefix: 'CHUNKED' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateChunkedGuard: guard.evaluate,
  summarizeChunkedGuard: guard.summarize,
  describeChunkedGuard: guard.describe,
};
