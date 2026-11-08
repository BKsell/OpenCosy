'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'topicsapi', prefix: 'TOPICSAPI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTopicsapiGuard: guard.evaluate,
  summarizeTopicsapiGuard: guard.summarize,
  describeTopicsapiGuard: guard.describe,
};
