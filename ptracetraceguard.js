'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ptracetrace', prefix: 'PTRACETRA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePtracetraceGuard: guard.evaluate,
  summarizePtracetraceGuard: guard.summarize,
  describePtracetraceGuard: guard.describe,
};
