'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ffi', prefix: 'FFI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFfiGuard: guard.evaluate,
  summarizeFfiGuard: guard.summarize,
  describeFfiGuard: guard.describe,
};
