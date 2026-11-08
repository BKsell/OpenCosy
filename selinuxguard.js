'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'selinux', prefix: 'SELINUX' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSelinuxGuard: guard.evaluate,
  summarizeSelinuxGuard: guard.summarize,
  describeSelinuxGuard: guard.describe,
};
