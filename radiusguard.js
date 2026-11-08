'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'radius', prefix: 'RADIUS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRadiusGuard: guard.evaluate,
  summarizeRadiusGuard: guard.summarize,
  describeRadiusGuard: guard.describe,
};
