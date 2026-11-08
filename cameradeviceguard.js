'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cameradevice', prefix: 'CAMERADEV' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCameradeviceGuard: guard.evaluate,
  summarizeCameradeviceGuard: guard.summarize,
  describeCameradeviceGuard: guard.describe,
};
