'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'baseuri', prefix: 'BASEURI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBaseuriGuard: guard.evaluate,
  summarizeBaseuriGuard: guard.summarize,
  describeBaseuriGuard: guard.describe,
};
