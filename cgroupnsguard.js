'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cgroupns', prefix: 'CGROUPNS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCgroupnsGuard: guard.evaluate,
  summarizeCgroupnsGuard: guard.summarize,
  describeCgroupnsGuard: guard.describe,
};
