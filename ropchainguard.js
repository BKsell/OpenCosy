'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ropchain', prefix: 'ROPCHAIN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRopchainGuard: guard.evaluate,
  summarizeRopchainGuard: guard.summarize,
  describeRopchainGuard: guard.describe,
};
