'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'nativeaddon', prefix: 'NATIVEADD' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNativeaddonGuard: guard.evaluate,
  summarizeNativeaddonGuard: guard.summarize,
  describeNativeaddonGuard: guard.describe,
};
