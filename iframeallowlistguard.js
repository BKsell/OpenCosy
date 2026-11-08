'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'IFRAMEALL', label: 'iframe allow 白名单' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateIframeallowlist: guard.evaluate,
  summarizeIframeallowlist: guard.summarize,
  describeIframeallowlist: guard.describe,
};
