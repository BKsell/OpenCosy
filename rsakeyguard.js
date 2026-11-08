'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'rsakey', prefix: 'RSAKEY' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRsakeyGuard: guard.evaluate,
  summarizeRsakeyGuard: guard.summarize,
  describeRsakeyGuard: guard.describe,
};
