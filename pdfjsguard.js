'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'pdfjs', prefix: 'PDFJS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePdfjsGuard: guard.evaluate,
  summarizePdfjsGuard: guard.summarize,
  describePdfjsGuard: guard.describe,
};
