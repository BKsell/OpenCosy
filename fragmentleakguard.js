'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'fragmentleak', prefix: 'FRAGMENTL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFragmentleakGuard: guard.evaluate,
  summarizeFragmentleakGuard: guard.summarize,
  describeFragmentleakGuard: guard.describe,
};
