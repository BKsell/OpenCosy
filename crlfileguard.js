'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'crlfile', prefix: 'CRLFILE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCrlfileGuard: guard.evaluate,
  summarizeCrlfileGuard: guard.summarize,
  describeCrlfileGuard: guard.describe,
};
