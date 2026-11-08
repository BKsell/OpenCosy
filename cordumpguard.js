'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cordump', prefix: 'CORDUMP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCordumpGuard: guard.evaluate,
  summarizeCordumpGuard: guard.summarize,
  describeCordumpGuard: guard.describe,
};
