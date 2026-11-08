'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ecsmeta', prefix: 'ECSMETA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEcsmetaGuard: guard.evaluate,
  summarizeEcsmetaGuard: guard.summarize,
  describeEcsmetaGuard: guard.describe,
};
