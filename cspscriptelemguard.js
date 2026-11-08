'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cspscriptelem', prefix: 'CSPSCRIPT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCspscriptelemGuard: guard.evaluate,
  summarizeCspscriptelemGuard: guard.summarize,
  describeCspscriptelemGuard: guard.describe,
};
