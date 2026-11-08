'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'willnavigate', prefix: 'WILLNAVIG' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWillnavigateGuard: guard.evaluate,
  summarizeWillnavigateGuard: guard.summarize,
  describeWillnavigateGuard: guard.describe,
};
