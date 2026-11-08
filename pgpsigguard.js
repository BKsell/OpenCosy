'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'pgpsig', prefix: 'PGPSIG' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePgpsigGuard: guard.evaluate,
  summarizePgpsigGuard: guard.summarize,
  describePgpsigGuard: guard.describe,
};
