'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'smepbit', prefix: 'SMEPBIT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSmepbitGuard: guard.evaluate,
  summarizeSmepbitGuard: guard.summarize,
  describeSmepbitGuard: guard.describe,
};
