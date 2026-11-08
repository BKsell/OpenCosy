'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'hardlink', prefix: 'HARDLINK' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHardlinkGuard: guard.evaluate,
  summarizeHardlinkGuard: guard.summarize,
  describeHardlinkGuard: guard.describe,
};
