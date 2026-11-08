'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'cname', prefix: 'CNAME' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCnameGuard: guard.evaluate,
  summarizeCnameGuard: guard.summarize,
  describeCnameGuard: guard.describe,
};
