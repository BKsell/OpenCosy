'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'prerender', prefix: 'PRERENDER' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePrerenderGuard: guard.evaluate,
  summarizePrerenderGuard: guard.summarize,
  describePrerenderGuard: guard.describe,
};
