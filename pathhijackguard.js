'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'pathhijack', prefix: 'PATHHIJAC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePathhijackGuard: guard.evaluate,
  summarizePathhijackGuard: guard.summarize,
  describePathhijackGuard: guard.describe,
};
