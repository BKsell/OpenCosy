'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cspstyleelem', prefix: 'CSPSTYLEE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCspstyleelemGuard: guard.evaluate,
  summarizeCspstyleelemGuard: guard.summarize,
  describeCspstyleelemGuard: guard.describe,
};
