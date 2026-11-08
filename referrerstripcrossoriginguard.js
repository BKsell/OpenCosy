'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'REFERRERS', label: '跨域 Referrer 剥离' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateReferrerstripcrossorigin: guard.evaluate,
  summarizeReferrerstripcrossorigin: guard.summarize,
  describeReferrerstripcrossorigin: guard.describe,
};
