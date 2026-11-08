'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ciphersuite', prefix: 'CIPHERSUI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCiphersuiteGuard: guard.evaluate,
  summarizeCiphersuiteGuard: guard.summarize,
  describeCiphersuiteGuard: guard.describe,
};
