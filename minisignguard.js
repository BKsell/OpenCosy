'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'minisign', prefix: 'MINISIGN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMinisignGuard: guard.evaluate,
  summarizeMinisignGuard: guard.summarize,
  describeMinisignGuard: guard.describe,
};
