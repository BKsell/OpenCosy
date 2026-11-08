'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'transferencoding', prefix: 'TRANSFERE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTransferencodingGuard: guard.evaluate,
  summarizeTransferencodingGuard: guard.summarize,
  describeTransferencodingGuard: guard.describe,
};
