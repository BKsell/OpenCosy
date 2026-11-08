'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'wifi', prefix: 'WIFI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWifiGuard: guard.evaluate,
  summarizeWifiGuard: guard.summarize,
  describeWifiGuard: guard.describe,
};
