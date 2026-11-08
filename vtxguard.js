'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'vtx', prefix: 'VTX' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateVtxGuard: guard.evaluate,
  summarizeVtxGuard: guard.summarize,
  describeVtxGuard: guard.describe,
};
