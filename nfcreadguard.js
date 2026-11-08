'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'nfcread', prefix: 'NFCREAD' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNfcreadGuard: guard.evaluate,
  summarizeNfcreadGuard: guard.summarize,
  describeNfcreadGuard: guard.describe,
};
