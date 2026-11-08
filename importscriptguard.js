'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'importscript', prefix: 'IMPORTSCR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateImportscriptGuard: guard.evaluate,
  summarizeImportscriptGuard: guard.summarize,
  describeImportscriptGuard: guard.describe,
};
