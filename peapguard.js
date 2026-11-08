'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'peap', prefix: 'PEAP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePeapGuard: guard.evaluate,
  summarizePeapGuard: guard.summarize,
  describePeapGuard: guard.describe,
};
