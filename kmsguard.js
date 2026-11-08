'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'kms', prefix: 'KMS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateKmsGuard: guard.evaluate,
  summarizeKmsGuard: guard.summarize,
  describeKmsGuard: guard.describe,
};
