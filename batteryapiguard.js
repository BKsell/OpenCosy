'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'batteryapi', prefix: 'BATTERYAP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBatteryapiGuard: guard.evaluate,
  summarizeBatteryapiGuard: guard.summarize,
  describeBatteryapiGuard: guard.describe,
};
