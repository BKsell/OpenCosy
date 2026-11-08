'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'newwindow', prefix: 'NEWWINDOW' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNewwindowGuard: guard.evaluate,
  summarizeNewwindowGuard: guard.summarize,
  describeNewwindowGuard: guard.describe,
};
