'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'devicefile', prefix: 'DEVICEFIL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDevicefileGuard: guard.evaluate,
  summarizeDevicefileGuard: guard.summarize,
  describeDevicefileGuard: guard.describe,
};
