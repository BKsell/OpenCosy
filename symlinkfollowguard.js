'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'symlinkfollow', prefix: 'SYMLINKFO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSymlinkfollowGuard: guard.evaluate,
  summarizeSymlinkfollowGuard: guard.summarize,
  describeSymlinkfollowGuard: guard.describe,
};
