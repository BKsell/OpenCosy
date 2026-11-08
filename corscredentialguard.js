'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'corscredential', prefix: 'CORSCREDE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCorscredentialGuard: guard.evaluate,
  summarizeCorscredentialGuard: guard.summarize,
  describeCorscredentialGuard: guard.describe,
};
