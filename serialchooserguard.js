'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'serialchooser', prefix: 'SERIALCHO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSerialchooserGuard: guard.evaluate,
  summarizeSerialchooserGuard: guard.summarize,
  describeSerialchooserGuard: guard.describe,
};
