'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'feecap', prefix: 'FEECAP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFeecapGuard: guard.evaluate,
  summarizeFeecapGuard: guard.summarize,
  describeFeecapGuard: guard.describe,
};
