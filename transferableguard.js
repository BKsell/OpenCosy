'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'transferable', prefix: 'TRANSFERA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTransferableGuard: guard.evaluate,
  summarizeTransferableGuard: guard.summarize,
  describeTransferableGuard: guard.describe,
};
