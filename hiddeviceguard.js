'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'hiddevice', prefix: 'HIDDEVICE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHiddeviceGuard: guard.evaluate,
  summarizeHiddeviceGuard: guard.summarize,
  describeHiddeviceGuard: guard.describe,
};
