'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'httpequiv', prefix: 'HTTPEQUIV' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHttpequivGuard: guard.evaluate,
  summarizeHttpequivGuard: guard.summarize,
  describeHttpequivGuard: guard.describe,
};
