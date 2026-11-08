'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'toolbarlayout', prefix: 'TOOLBARLA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateToolbarlayoutGuard: guard.evaluate,
  summarizeToolbarlayoutGuard: guard.summarize,
  describeToolbarlayoutGuard: guard.describe,
};
