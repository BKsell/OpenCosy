'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'nel', prefix: 'NEL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNelGuard: guard.evaluate,
  summarizeNelGuard: guard.summarize,
  describeNelGuard: guard.describe,
};
