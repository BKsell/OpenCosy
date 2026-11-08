'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'siv', prefix: 'SIV' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSivGuard: guard.evaluate,
  summarizeSivGuard: guard.summarize,
  describeSivGuard: guard.describe,
};
