'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'microphone', prefix: 'MICROPHON' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMicrophoneGuard: guard.evaluate,
  summarizeMicrophoneGuard: guard.summarize,
  describeMicrophoneGuard: guard.describe,
};
