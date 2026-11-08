'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ssl', prefix: 'SSL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSslGuard: guard.evaluate,
  summarizeSslGuard: guard.summarize,
  describeSslGuard: guard.describe,
};
