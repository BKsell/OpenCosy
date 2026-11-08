'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'networkinfoapi', prefix: 'NETWORKIN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNetworkinfoapiGuard: guard.evaluate,
  summarizeNetworkinfoapiGuard: guard.summarize,
  describeNetworkinfoapiGuard: guard.describe,
};
