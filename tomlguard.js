'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'toml', prefix: 'TOML' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTomlGuard: guard.evaluate,
  summarizeTomlGuard: guard.summarize,
  describeTomlGuard: guard.describe,
};
