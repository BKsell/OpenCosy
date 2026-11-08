'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'atapass', prefix: 'ATAPASS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAtapassGuard: guard.evaluate,
  summarizeAtapassGuard: guard.summarize,
  describeAtapassGuard: guard.describe,
};
