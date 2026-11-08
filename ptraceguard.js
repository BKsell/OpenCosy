'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ptrace', prefix: 'PTRACE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePtraceGuard: guard.evaluate,
  summarizePtraceGuard: guard.summarize,
  describePtraceGuard: guard.describe,
};
