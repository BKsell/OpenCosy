'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'keyboardlock', prefix: 'KEYBOARDL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateKeyboardlockGuard: guard.evaluate,
  summarizeKeyboardlockGuard: guard.summarize,
  describeKeyboardlockGuard: guard.describe,
};
