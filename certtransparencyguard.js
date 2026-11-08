'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'certtransparency', prefix: 'CERTTRANS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCerttransparencyGuard: guard.evaluate,
  summarizeCerttransparencyGuard: guard.summarize,
  describeCerttransparencyGuard: guard.describe,
};
