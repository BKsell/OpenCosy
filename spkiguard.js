'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'spki', prefix: 'SPKI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSpkiGuard: guard.evaluate,
  summarizeSpkiGuard: guard.summarize,
  describeSpkiGuard: guard.describe,
};
