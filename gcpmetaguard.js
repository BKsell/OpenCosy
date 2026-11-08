'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'gcpmeta', prefix: 'GCPMETA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateGcpmetaGuard: guard.evaluate,
  summarizeGcpmetaGuard: guard.summarize,
  describeGcpmetaGuard: guard.describe,
};
