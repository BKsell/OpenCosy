'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'videocapture', prefix: 'VIDEOCAPT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateVideocaptureGuard: guard.evaluate,
  summarizeVideocaptureGuard: guard.summarize,
  describeVideocaptureGuard: guard.describe,
};
