'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'notarization', prefix: 'NOTARIZAT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNotarizationGuard: guard.evaluate,
  summarizeNotarizationGuard: guard.summarize,
  describeNotarizationGuard: guard.describe,
};
