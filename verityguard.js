'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'verity', prefix: 'VERITY' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateVerityGuard: guard.evaluate,
  summarizeVerityGuard: guard.summarize,
  describeVerityGuard: guard.describe,
};
