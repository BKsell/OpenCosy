'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'webrtc', prefix: 'WEBRTC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWebrtcGuard: guard.evaluate,
  summarizeWebrtcGuard: guard.summarize,
  describeWebrtcGuard: guard.describe,
};
