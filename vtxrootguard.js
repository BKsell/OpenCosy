'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'vtxroot', prefix: 'VTXROOT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateVtxrootGuard: guard.evaluate,
  summarizeVtxrootGuard: guard.summarize,
  describeVtxrootGuard: guard.describe,
};
