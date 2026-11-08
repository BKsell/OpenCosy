'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'navigatoroverride', prefix: 'NAVIGATOR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateNavigatoroverrideGuard: guard.evaluate,
  summarizeNavigatoroverrideGuard: guard.summarize,
  describeNavigatoroverrideGuard: guard.describe,
};
