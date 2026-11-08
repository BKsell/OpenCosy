'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'jks', prefix: 'JKS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateJksGuard: guard.evaluate,
  summarizeJksGuard: guard.summarize,
  describeJksGuard: guard.describe,
};
