'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'teheader', prefix: 'TEHEADER' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTeheaderGuard: guard.evaluate,
  summarizeTeheaderGuard: guard.summarize,
  describeTeheaderGuard: guard.describe,
};
