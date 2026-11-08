'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'purl', prefix: 'PURL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePurlGuard: guard.evaluate,
  summarizePurlGuard: guard.summarize,
  describePurlGuard: guard.describe,
};
