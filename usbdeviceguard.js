'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'usbdevice', prefix: 'USBDEVICE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateUsbdeviceGuard: guard.evaluate,
  summarizeUsbdeviceGuard: guard.summarize,
  describeUsbdeviceGuard: guard.describe,
};
