'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'screencapture', prefix: 'SCREENCAP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateScreencaptureGuard: guard.evaluate,
  summarizeScreencaptureGuard: guard.summarize,
  describeScreencaptureGuard: guard.describe,
};
