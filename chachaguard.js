'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'chacha', prefix: 'CHACHA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateChachaGuard: guard.evaluate,
  summarizeChachaGuard: guard.summarize,
  describeChachaGuard: guard.describe,
};
