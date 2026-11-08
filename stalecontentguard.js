'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'stalecontent', prefix: 'STALECONT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateStalecontentGuard: guard.evaluate,
  summarizeStalecontentGuard: guard.summarize,
  describeStalecontentGuard: guard.describe,
};
