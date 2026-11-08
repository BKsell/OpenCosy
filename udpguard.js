'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'udp', prefix: 'UDP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateUdpGuard: guard.evaluate,
  summarizeUdpGuard: guard.summarize,
  describeUdpGuard: guard.describe,
};
