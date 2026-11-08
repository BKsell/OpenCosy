'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'bytebuddy', prefix: 'BYTEBUDDY' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBytebuddyGuard: guard.evaluate,
  summarizeBytebuddyGuard: guard.summarize,
  describeBytebuddyGuard: guard.describe,
};
