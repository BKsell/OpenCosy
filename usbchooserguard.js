'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'usbchooser', prefix: 'USBCHOOSE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateUsbchooserGuard: guard.evaluate,
  summarizeUsbchooserGuard: guard.summarize,
  describeUsbchooserGuard: guard.describe,
};
