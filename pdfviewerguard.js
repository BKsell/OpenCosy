'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'pdfviewer', prefix: 'PDFVIEWER' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePdfviewerGuard: guard.evaluate,
  summarizePdfviewerGuard: guard.summarize,
  describePdfviewerGuard: guard.describe,
};
