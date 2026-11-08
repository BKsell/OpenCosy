'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'kubernetes', prefix: 'KUBERNETE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateKubernetesGuard: guard.evaluate,
  summarizeKubernetesGuard: guard.summarize,
  describeKubernetesGuard: guard.describe,
};
