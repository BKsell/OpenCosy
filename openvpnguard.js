'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'openvpn', prefix: 'OPENVPN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOpenvpnGuard: guard.evaluate,
  summarizeOpenvpnGuard: guard.summarize,
  describeOpenvpnGuard: guard.describe,
};
