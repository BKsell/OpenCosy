'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'objectinject', prefix: 'OBJECTINJ' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateObjectinjectGuard: guard.evaluate,
  summarizeObjectinjectGuard: guard.summarize,
  describeObjectinjectGuard: guard.describe,
};
