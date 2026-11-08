'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'audiocapture', prefix: 'AUDIOCAPT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAudiocaptureGuard: guard.evaluate,
  summarizeAudiocaptureGuard: guard.summarize,
  describeAudiocaptureGuard: guard.describe,
};
