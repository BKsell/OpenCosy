'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'FETCHREDI', label: '重定向次数' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFetchredirectlimit: guard.evaluate,
  summarizeFetchredirectlimit: guard.summarize,
  describeFetchredirectlimit: guard.describe,
};
