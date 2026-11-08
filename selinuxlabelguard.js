'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'selinuxlabel', prefix: 'SELINUXLA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSelinuxlabelGuard: guard.evaluate,
  summarizeSelinuxlabelGuard: guard.summarize,
  describeSelinuxlabelGuard: guard.describe,
};
