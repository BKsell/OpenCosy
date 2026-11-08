'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'corspolicy', prefix: 'CORSPOLIC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCorspolicyGuard: guard.evaluate,
  summarizeCorspolicyGuard: guard.summarize,
  describeCorspolicyGuard: guard.describe,
};
