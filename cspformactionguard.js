'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cspformaction', prefix: 'CSPFORMAC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCspformactionGuard: guard.evaluate,
  summarizeCspformactionGuard: guard.summarize,
  describeCspformactionGuard: guard.describe,
};
