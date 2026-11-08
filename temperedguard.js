'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'tempered', prefix: 'TEMPERED' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTemperedGuard: guard.evaluate,
  summarizeTemperedGuard: guard.summarize,
  describeTemperedGuard: guard.describe,
};
