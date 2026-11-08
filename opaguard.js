'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'opa', prefix: 'OPA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOpaGuard: guard.evaluate,
  summarizeOpaGuard: guard.summarize,
  describeOpaGuard: guard.describe,
};
