'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'officemacro', prefix: 'OFFICEMAC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOfficemacroGuard: guard.evaluate,
  summarizeOfficemacroGuard: guard.summarize,
  describeOfficemacroGuard: guard.describe,
};
