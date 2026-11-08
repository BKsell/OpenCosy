'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'serviceworker', prefix: 'SERVICEWO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateServiceworkerGuard: guard.evaluate,
  summarizeServiceworkerGuard: guard.summarize,
  describeServiceworkerGuard: guard.describe,
};
