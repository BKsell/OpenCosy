'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'yescrypt', prefix: 'YESCRYPT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateYescryptGuard: guard.evaluate,
  summarizeYescryptGuard: guard.summarize,
  describeYescryptGuard: guard.describe,
};
