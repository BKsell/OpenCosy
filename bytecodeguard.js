'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'bytecode', prefix: 'BYTECODE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBytecodeGuard: guard.evaluate,
  summarizeBytecodeGuard: guard.summarize,
  describeBytecodeGuard: guard.describe,
};
