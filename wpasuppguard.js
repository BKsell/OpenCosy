'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'wpasupp', prefix: 'WPASUPP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWpasuppGuard: guard.evaluate,
  summarizeWpasuppGuard: guard.summarize,
  describeWpasuppGuard: guard.describe,
};
