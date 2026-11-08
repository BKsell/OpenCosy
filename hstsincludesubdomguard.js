'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'hstsincludesubdom', prefix: 'HSTSINCLU' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHstsincludesubdomGuard: guard.evaluate,
  summarizeHstsincludesubdomGuard: guard.summarize,
  describeHstsincludesubdomGuard: guard.describe,
};
