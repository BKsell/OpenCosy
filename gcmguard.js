'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'gcm', prefix: 'GCM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateGcmGuard: guard.evaluate,
  summarizeGcmGuard: guard.summarize,
  describeGcmGuard: guard.describe,
};
