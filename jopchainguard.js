'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'jopchain', prefix: 'JOPCHAIN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateJopchainGuard: guard.evaluate,
  summarizeJopchainGuard: guard.summarize,
  describeJopchainGuard: guard.describe,
};
