'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'pidns', prefix: 'PIDNS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePidnsGuard: guard.evaluate,
  summarizePidnsGuard: guard.summarize,
  describePidnsGuard: guard.describe,
};
