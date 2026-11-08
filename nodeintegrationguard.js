'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'nodeintegration', prefix: 'NODEINTEG' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNodeintegrationGuard: guard.evaluate,
  summarizeNodeintegrationGuard: guard.summarize,
  describeNodeintegrationGuard: guard.describe,
};
