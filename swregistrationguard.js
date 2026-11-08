'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'swregistration', prefix: 'SWREGISTR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSwregistrationGuard: guard.evaluate,
  summarizeSwregistrationGuard: guard.summarize,
  describeSwregistrationGuard: guard.describe,
};
