'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'iommu', prefix: 'IOMMU' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateIommuGuard: guard.evaluate,
  summarizeIommuGuard: guard.summarize,
  describeIommuGuard: guard.describe,
};
