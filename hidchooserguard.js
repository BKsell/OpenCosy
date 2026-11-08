'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'hidchooser', prefix: 'HIDCHOOSE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHidchooserGuard: guard.evaluate,
  summarizeHidchooserGuard: guard.summarize,
  describeHidchooserGuard: guard.describe,
};
