'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'aes', prefix: 'AES' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAesGuard: guard.evaluate,
  summarizeAesGuard: guard.summarize,
  describeAesGuard: guard.describe,
};
