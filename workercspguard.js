'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'workercsp', prefix: 'WORKERCSP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWorkercspGuard: guard.evaluate,
  summarizeWorkercspGuard: guard.summarize,
  describeWorkercspGuard: guard.describe,
};
