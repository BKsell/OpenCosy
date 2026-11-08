'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'desync', prefix: 'DESYNC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDesyncGuard: guard.evaluate,
  summarizeDesyncGuard: guard.summarize,
  describeDesyncGuard: guard.describe,
};
