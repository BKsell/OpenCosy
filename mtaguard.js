'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'mta', prefix: 'MTA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMtaGuard: guard.evaluate,
  summarizeMtaGuard: guard.summarize,
  describeMtaGuard: guard.describe,
};
