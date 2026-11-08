'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'staple', prefix: 'STAPLE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateStapleGuard: guard.evaluate,
  summarizeStapleGuard: guard.summarize,
  describeStapleGuard: guard.describe,
};
