'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'udev', prefix: 'UDEV' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateUdevGuard: guard.evaluate,
  summarizeUdevGuard: guard.summarize,
  describeUdevGuard: guard.describe,
};
