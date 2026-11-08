'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'nameclash', prefix: 'NAMECLASH' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNameclashGuard: guard.evaluate,
  summarizeNameclashGuard: guard.summarize,
  describeNameclashGuard: guard.describe,
};
