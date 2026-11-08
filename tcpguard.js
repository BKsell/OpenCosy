'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tcp', prefix: 'TCP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTcpGuard: guard.evaluate,
  summarizeTcpGuard: guard.summarize,
  describeTcpGuard: guard.describe,
};
