'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'networkquality', prefix: 'NETWORKQU' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNetworkqualityGuard: guard.evaluate,
  summarizeNetworkqualityGuard: guard.summarize,
  describeNetworkqualityGuard: guard.describe,
};
