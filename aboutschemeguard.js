'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'aboutscheme', prefix: 'ABOUTSCHE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAboutschemeGuard: guard.evaluate,
  summarizeAboutschemeGuard: guard.summarize,
  describeAboutschemeGuard: guard.describe,
};
