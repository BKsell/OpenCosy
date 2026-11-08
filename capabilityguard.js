'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'capability', prefix: 'CAPABILIT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCapabilityGuard: guard.evaluate,
  summarizeCapabilityGuard: guard.summarize,
  describeCapabilityGuard: guard.describe,
};
