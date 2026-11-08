'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'mediaparser', prefix: 'MEDIAPARS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMediaparserGuard: guard.evaluate,
  summarizeMediaparserGuard: guard.summarize,
  describeMediaparserGuard: guard.describe,
};
