'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'terraform', prefix: 'TERRAFORM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTerraformGuard: guard.evaluate,
  summarizeTerraformGuard: guard.summarize,
  describeTerraformGuard: guard.describe,
};
