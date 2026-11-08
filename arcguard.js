'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'arc', prefix: 'ARC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateArcGuard: guard.evaluate,
  summarizeArcGuard: guard.summarize,
  describeArcGuard: guard.describe,
};
