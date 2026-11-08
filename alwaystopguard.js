'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'alwaystop', prefix: 'ALWAYSTOP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAlwaystopGuard: guard.evaluate,
  summarizeAlwaystopGuard: guard.summarize,
  describeAlwaystopGuard: guard.describe,
};
