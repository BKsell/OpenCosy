'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'jsurl', prefix: 'JSURL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateJsurlGuard: guard.evaluate,
  summarizeJsurlGuard: guard.summarize,
  describeJsurlGuard: guard.describe,
};
