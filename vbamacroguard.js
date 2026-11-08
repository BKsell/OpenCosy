'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'vbamacro', prefix: 'VBAMACRO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateVbamacroGuard: guard.evaluate,
  summarizeVbamacroGuard: guard.summarize,
  describeVbamacroGuard: guard.describe,
};
