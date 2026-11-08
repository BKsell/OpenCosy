'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'aboutblank', prefix: 'ABOUTBLAN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAboutblankGuard: guard.evaluate,
  summarizeAboutblankGuard: guard.summarize,
  describeAboutblankGuard: guard.describe,
};
