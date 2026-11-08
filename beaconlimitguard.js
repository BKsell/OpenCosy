'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'beaconlimit', prefix: 'BEACONLIM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBeaconlimitGuard: guard.evaluate,
  summarizeBeaconlimitGuard: guard.summarize,
  describeBeaconlimitGuard: guard.describe,
};
