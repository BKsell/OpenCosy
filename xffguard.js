'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'xff', prefix: 'XFF' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateXffGuard: guard.evaluate,
  summarizeXffGuard: guard.summarize,
  describeXffGuard: guard.describe,
};
