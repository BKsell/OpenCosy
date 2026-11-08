'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'shellopen', prefix: 'SHELLOPEN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateShellopenGuard: guard.evaluate,
  summarizeShellopenGuard: guard.summarize,
  describeShellopenGuard: guard.describe,
};
