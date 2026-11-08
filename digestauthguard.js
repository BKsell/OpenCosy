'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'digestauth', prefix: 'DIGESTAUT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDigestauthGuard: guard.evaluate,
  summarizeDigestauthGuard: guard.summarize,
  describeDigestauthGuard: guard.describe,
};
