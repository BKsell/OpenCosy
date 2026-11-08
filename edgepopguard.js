'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'edgepop', prefix: 'EDGEPOP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEdgepopGuard: guard.evaluate,
  summarizeEdgepopGuard: guard.summarize,
  describeEdgepopGuard: guard.describe,
};
