'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'httponly', prefix: 'HTTPONLY' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHttponlyGuard: guard.evaluate,
  summarizeHttponlyGuard: guard.summarize,
  describeHttponlyGuard: guard.describe,
};
