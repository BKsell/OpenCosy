'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'canarystack', prefix: 'CANARYSTA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCanarystackGuard: guard.evaluate,
  summarizeCanarystackGuard: guard.summarize,
  describeCanarystackGuard: guard.describe,
};
