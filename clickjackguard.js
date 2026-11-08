'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'clickjack', prefix: 'CLICKJACK' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateClickjackGuard: guard.evaluate,
  summarizeClickjackGuard: guard.summarize,
  describeClickjackGuard: guard.describe,
};
