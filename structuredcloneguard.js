'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'structuredclone', prefix: 'STRUCTURE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateStructuredcloneGuard: guard.evaluate,
  summarizeStructuredcloneGuard: guard.summarize,
  describeStructuredcloneGuard: guard.describe,
};
