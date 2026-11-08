'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'redfish', prefix: 'REDFISH' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRedfishGuard: guard.evaluate,
  summarizeRedfishGuard: guard.summarize,
  describeRedfishGuard: guard.describe,
};
