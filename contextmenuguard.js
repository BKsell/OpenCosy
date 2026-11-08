'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'contextmenu', prefix: 'CONTEXTME' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateContextmenuGuard: guard.evaluate,
  summarizeContextmenuGuard: guard.summarize,
  describeContextmenuGuard: guard.describe,
};
