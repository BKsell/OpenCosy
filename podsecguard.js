'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'podsec', prefix: 'PODSEC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePodsecGuard: guard.evaluate,
  summarizePodsecGuard: guard.summarize,
  describePodsecGuard: guard.describe,
};
