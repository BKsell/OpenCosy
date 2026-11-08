'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'relro', prefix: 'RELRO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRelroGuard: guard.evaluate,
  summarizeRelroGuard: guard.summarize,
  describeRelroGuard: guard.describe,
};
