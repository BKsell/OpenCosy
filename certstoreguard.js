'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'certstore', prefix: 'CERTSTORE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCertstoreGuard: guard.evaluate,
  summarizeCertstoreGuard: guard.summarize,
  describeCertstoreGuard: guard.describe,
};
