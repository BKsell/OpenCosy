'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cipherorder', prefix: 'CIPHERORD' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCipherorderGuard: guard.evaluate,
  summarizeCipherorderGuard: guard.summarize,
  describeCipherorderGuard: guard.describe,
};
