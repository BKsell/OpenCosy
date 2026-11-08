'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'unicode', prefix: 'UNICODE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateUnicodeGuard: guard.evaluate,
  summarizeUnicodeGuard: guard.summarize,
  describeUnicodeGuard: guard.describe,
};
