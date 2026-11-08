'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tabcontextmenu', prefix: 'TABCONTEX' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTabcontextmenuGuard: guard.evaluate,
  summarizeTabcontextmenuGuard: guard.summarize,
  describeTabcontextmenuGuard: guard.describe,
};
