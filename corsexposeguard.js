'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'corsexpose', prefix: 'CORSEXPOS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCorsexposeGuard: guard.evaluate,
  summarizeCorsexposeGuard: guard.summarize,
  describeCorsexposeGuard: guard.describe,
};
