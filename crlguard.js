'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'crl', prefix: 'CRL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCrlGuard: guard.evaluate,
  summarizeCrlGuard: guard.summarize,
  describeCrlGuard: guard.describe,
};
