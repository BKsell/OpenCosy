'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'highcontrast', prefix: 'HIGHCONTR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHighcontrastGuard: guard.evaluate,
  summarizeHighcontrastGuard: guard.summarize,
  describeHighcontrastGuard: guard.describe,
};
