'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'inode', prefix: 'INODE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateInodeGuard: guard.evaluate,
  summarizeInodeGuard: guard.summarize,
  describeInodeGuard: guard.describe,
};
