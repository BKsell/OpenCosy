'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'nativehost', prefix: 'NATIVEHOS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNativehostGuard: guard.evaluate,
  summarizeNativehostGuard: guard.summarize,
  describeNativehostGuard: guard.describe,
};
