'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cgroup', prefix: 'CGROUP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCgroupGuard: guard.evaluate,
  summarizeCgroupGuard: guard.summarize,
  describeCgroupGuard: guard.describe,
};
