'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'hid', prefix: 'HID' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHidGuard: guard.evaluate,
  summarizeHidGuard: guard.summarize,
  describeHidGuard: guard.describe,
};
