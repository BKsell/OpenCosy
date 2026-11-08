'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tabaudio', prefix: 'TABAUDIO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTabaudioGuard: guard.evaluate,
  summarizeTabaudioGuard: guard.summarize,
  describeTabaudioGuard: guard.describe,
};
