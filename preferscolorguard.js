'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'preferscolor', prefix: 'PREFERSCO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePreferscolorGuard: guard.evaluate,
  summarizePreferscolorGuard: guard.summarize,
  describePreferscolorGuard: guard.describe,
};
