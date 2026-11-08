'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'homograph', prefix: 'HOMOGRAPH' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHomographGuard: guard.evaluate,
  summarizeHomographGuard: guard.summarize,
  describeHomographGuard: guard.describe,
};
