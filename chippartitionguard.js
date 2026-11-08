'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'chippartition', prefix: 'CHIPPARTI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateChippartitionGuard: guard.evaluate,
  summarizeChippartitionGuard: guard.summarize,
  describeChippartitionGuard: guard.describe,
};
