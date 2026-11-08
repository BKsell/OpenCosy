'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'videojail', prefix: 'VIDEOJAIL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateVideojailGuard: guard.evaluate,
  summarizeVideojailGuard: guard.summarize,
  describeVideojailGuard: guard.describe,
};
