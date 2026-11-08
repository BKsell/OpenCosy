'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'iommuaddr', prefix: 'IOMMUADDR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateIommuaddrGuard: guard.evaluate,
  summarizeIommuaddrGuard: guard.summarize,
  describeIommuaddrGuard: guard.describe,
};
