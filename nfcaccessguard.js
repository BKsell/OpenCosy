'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'nfcaccess', prefix: 'NFCACCESS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNfcaccessGuard: guard.evaluate,
  summarizeNfcaccessGuard: guard.summarize,
  describeNfcaccessGuard: guard.describe,
};
