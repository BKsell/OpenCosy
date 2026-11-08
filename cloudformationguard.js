'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cloudformation', prefix: 'CLOUDFORM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCloudformationGuard: guard.evaluate,
  summarizeCloudformationGuard: guard.summarize,
  describeCloudformationGuard: guard.describe,
};
