'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'des', prefix: 'DES' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDesGuard: guard.evaluate,
  summarizeDesGuard: guard.summarize,
  describeDesGuard: guard.describe,
};
