'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'firmware', prefix: 'FIRMWARE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFirmwareGuard: guard.evaluate,
  summarizeFirmwareGuard: guard.summarize,
  describeFirmwareGuard: guard.describe,
};
