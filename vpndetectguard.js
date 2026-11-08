'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'vpndetect', prefix: 'VPNDETECT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateVpndetectGuard: guard.evaluate,
  summarizeVpndetectGuard: guard.summarize,
  describeVpndetectGuard: guard.describe,
};
