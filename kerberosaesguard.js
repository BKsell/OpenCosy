'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'kerberosaes', prefix: 'KERBEROSA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateKerberosaesGuard: guard.evaluate,
  summarizeKerberosaesGuard: guard.summarize,
  describeKerberosaesGuard: guard.describe,
};
