'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'capabilityset', prefix: 'CAPABILIT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCapabilitysetGuard: guard.evaluate,
  summarizeCapabilitysetGuard: guard.summarize,
  describeCapabilitysetGuard: guard.describe,
};
