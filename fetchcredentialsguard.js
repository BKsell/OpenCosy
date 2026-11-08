'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'FETCHCRED', label: '凭据模式' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFetchcredentials: guard.evaluate,
  summarizeFetchcredentials: guard.summarize,
  describeFetchcredentials: guard.describe,
};
