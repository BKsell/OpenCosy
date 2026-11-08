'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'routeadvert', prefix: 'ROUTEADVE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRouteadvertGuard: guard.evaluate,
  summarizeRouteadvertGuard: guard.summarize,
  describeRouteadvertGuard: guard.describe,
};
