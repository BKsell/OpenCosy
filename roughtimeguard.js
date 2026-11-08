'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'roughtime', prefix: 'ROUGHTIME' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRoughtimeGuard: guard.evaluate,
  summarizeRoughtimeGuard: guard.summarize,
  describeRoughtimeGuard: guard.describe,
};
