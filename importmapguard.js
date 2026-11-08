'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'importmap', prefix: 'IMPORTMAP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateImportmapGuard: guard.evaluate,
  summarizeImportmapGuard: guard.summarize,
  describeImportmapGuard: guard.describe,
};
