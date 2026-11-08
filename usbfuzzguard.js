'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'usbfuzz', prefix: 'USBFUZZ' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateUsbfuzzGuard: guard.evaluate,
  summarizeUsbfuzzGuard: guard.summarize,
  describeUsbfuzzGuard: guard.describe,
};
