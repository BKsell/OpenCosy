'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'floc', prefix: 'FLOC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFlocGuard: guard.evaluate,
  summarizeFlocGuard: guard.summarize,
  describeFlocGuard: guard.describe,
};
