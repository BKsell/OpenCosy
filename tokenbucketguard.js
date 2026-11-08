'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tokenbucket', prefix: 'TOKENBUCK' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTokenbucketGuard: guard.evaluate,
  summarizeTokenbucketGuard: guard.summarize,
  describeTokenbucketGuard: guard.describe,
};
