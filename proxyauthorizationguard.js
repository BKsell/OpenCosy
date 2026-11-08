'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'PROXYAUTH', label: '代理认证头' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateProxyauthorization: guard.evaluate,
  summarizeProxyauthorization: guard.summarize,
  describeProxyauthorization: guard.describe,
};
