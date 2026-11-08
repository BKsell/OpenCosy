'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'beaconapi', prefix: 'BEACONAPI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBeaconapiGuard: guard.evaluate,
  summarizeBeaconapiGuard: guard.summarize,
  describeBeaconapiGuard: guard.describe,
};
