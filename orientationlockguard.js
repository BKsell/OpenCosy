'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'orientationlock', prefix: 'ORIENTATI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOrientationlockGuard: guard.evaluate,
  summarizeOrientationlockGuard: guard.summarize,
  describeOrientationlockGuard: guard.describe,
};
