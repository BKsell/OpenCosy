'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cbor', prefix: 'CBOR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCborGuard: guard.evaluate,
  summarizeCborGuard: guard.summarize,
  describeCborGuard: guard.describe,
};
