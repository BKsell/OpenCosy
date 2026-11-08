'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'pipwindow', prefix: 'PIPWINDOW' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePipwindowGuard: guard.evaluate,
  summarizePipwindowGuard: guard.summarize,
  describePipwindowGuard: guard.describe,
};
