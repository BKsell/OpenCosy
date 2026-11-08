'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'hstsheader', prefix: 'HSTSHEADE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHstsheaderGuard: guard.evaluate,
  summarizeHstsheaderGuard: guard.summarize,
  describeHstsheaderGuard: guard.describe,
};
