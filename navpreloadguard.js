'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'navpreload', prefix: 'NAVPRELOA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNavpreloadGuard: guard.evaluate,
  summarizeNavpreloadGuard: guard.summarize,
  describeNavpreloadGuard: guard.describe,
};
