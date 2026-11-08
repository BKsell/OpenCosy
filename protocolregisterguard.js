'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'protocolregister', prefix: 'PROTOCOLR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateProtocolregisterGuard: guard.evaluate,
  summarizeProtocolregisterGuard: guard.summarize,
  describeProtocolregisterGuard: guard.describe,
};
