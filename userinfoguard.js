'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'userinfo', prefix: 'USERINFO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateUserinfoGuard: guard.evaluate,
  summarizeUserinfoGuard: guard.summarize,
  describeUserinfoGuard: guard.describe,
};
